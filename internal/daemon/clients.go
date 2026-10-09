package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/chetankar/openpass/internal/client"
)

const (
	StatePending  = "pending"
	StateApproved = "approved"

	RevealAlways = "always"
	RevealPrompt = "prompt"
	RevealNever  = "never"

	pairingTTL   = 2 * time.Minute
	replayWindow = 30 * time.Second
)

var (
	ErrNotPaired      = errors.New("client is not paired")
	ErrDeniedByPolicy = errors.New("denied by policy")
)

type Policy struct {
	Reveal string `json:"reveal"`

	// Methods a client may call. Empty means no restriction, which is what the
	// CLI gets. A browser gets a read-only set: pairing gates who is talking,
	// this gates what they can do.
	Methods []string `json:"methods,omitempty"`
}

// Allows reports whether the policy permits a method.
func (p Policy) Allows(method string) bool {
	if len(p.Methods) == 0 {
		return true
	}
	for _, m := range p.Methods {
		if m == method {
			return true
		}
	}
	return false
}

// browserMethods is everything a browser extension needs and nothing more. It
// can find and read logins; it cannot delete, rename, or manage other clients.
var browserMethods = []string{
	"status",
	"vault.match",
	"vault.list",
	"vault.get",
}

type ClientRecord struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	PubKey    []byte    `json:"pubkey"`
	State     string    `json:"state"`
	Policy    Policy    `json:"policy"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

type pendingPair struct {
	record  *ClientRecord
	code    string
	expires time.Time
}

// Registry tracks which clients may talk to the daemon and what each is
// allowed to do.
type Registry struct {
	mu      sync.Mutex
	path    string
	clients map[string]*ClientRecord
	pending map[string]*pendingPair
	nonces  map[string]time.Time
}

func NewRegistry(path string) (*Registry, error) {
	r := &Registry{
		path:    path,
		clients: map[string]*ClientRecord{},
		pending: map[string]*pendingPair{},
		nonces:  map[string]time.Time{},
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return r, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}

	var stored struct {
		Clients []*ClientRecord `json:"clients"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, fmt.Errorf("failed to parse %s: %w", path, err)
	}
	for _, c := range stored.Clients {
		r.clients[c.ID] = c
	}
	return r, nil
}

// Empty reports whether any client has ever registered. The first one
// self-approves; see Pair.
func (r *Registry) Empty() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.clients) == 0
}

// Pair registers a client. The first client ever to register is approved
// automatically: it can already read clients.json and the key file beside it,
// so requiring approval from an approved client it would have to be would
// leave nothing able to bootstrap. Every later client waits for a human.
func (r *Registry) Pair(name, kind string, pub ed25519.PublicKey) (*ClientRecord, string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, "", errors.New("malformed public key")
	}
	if name == "" || kind == "" {
		return nil, "", errors.New("name and kind are required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	id := client.DeriveClientID(kind, pub)
	if existing, ok := r.clients[id]; ok {
		return existing, "", nil
	}

	// Pairing is idempotent: a client that calls again before being approved
	// gets its existing code back, not a second pending record.
	r.expirePendingLocked()
	for _, p := range r.pending {
		if p.record.ID == id {
			return p.record, p.code, nil
		}
	}

	record := &ClientRecord{
		ID:        id,
		Name:      name,
		Kind:      kind,
		PubKey:    pub,
		State:     StatePending,
		Policy:    defaultPolicy(kind),
		CreatedAt: time.Now().UTC(),
	}

	if len(r.clients) == 0 {
		record.State = StateApproved
		r.clients[id] = record
		return record, "", r.saveLocked()
	}

	code, err := pairingCode()
	if err != nil {
		return nil, "", err
	}
	r.pending[code] = &pendingPair{record: record, code: code, expires: time.Now().Add(pairingTTL)}
	return record, code, nil
}

// Approve moves a pending client to approved.
func (r *Registry) Approve(code string) (*ClientRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.expirePendingLocked()

	p, ok := r.pending[code]
	if !ok {
		return nil, fmt.Errorf("no pending client with code %q", code)
	}
	delete(r.pending, code)

	p.record.State = StateApproved
	r.clients[p.record.ID] = p.record
	return p.record, r.saveLocked()
}

func (r *Registry) Revoke(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.clients[id]; !ok {
		return fmt.Errorf("no client with id %q", id)
	}
	delete(r.clients, id)
	return r.saveLocked()
}

func (r *Registry) List() []ClientRecord {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.expirePendingLocked()

	out := make([]ClientRecord, 0, len(r.clients)+len(r.pending))
	for _, c := range r.clients {
		out = append(out, *c)
	}
	for _, p := range r.pending {
		out = append(out, *p.record)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Verify authenticates a request and returns the client that sent it.
func (r *Registry) Verify(auth *client.Auth, method string, params []byte) (*ClientRecord, error) {
	if auth == nil {
		return nil, fmt.Errorf("%w: request is unsigned", ErrNotPaired)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	record, ok := r.clients[auth.ClientID]
	if !ok || record.State != StateApproved {
		return nil, fmt.Errorf("%w: %s", ErrNotPaired, auth.ClientID)
	}

	skew := time.Since(time.Unix(auth.TS, 0))
	if skew < -replayWindow || skew > replayWindow {
		return nil, errors.New("request timestamp is outside the accepted window")
	}

	r.expireNoncesLocked()
	if _, seen := r.nonces[auth.Nonce]; seen {
		return nil, errors.New("nonce has already been used")
	}

	sig, err := base64.StdEncoding.DecodeString(auth.Sig)
	if err != nil {
		return nil, errors.New("malformed signature")
	}
	if !ed25519.Verify(record.PubKey, client.SigningString(method, params, auth.Nonce, auth.TS), sig) {
		return nil, errors.New("signature does not verify")
	}

	r.nonces[auth.Nonce] = time.Now()
	record.LastSeen = time.Now().UTC()
	return record, nil
}

// CanReveal reports whether a client may read a secret.
//
// "prompt" denies for now: there is no mechanism for a headless daemon to ask
// a human, so the only honest answer is no. Fail closed.
func CanReveal(record *ClientRecord) error {
	switch record.Policy.Reveal {
	case RevealAlways:
		return nil
	case RevealPrompt:
		return fmt.Errorf("%w: %s needs approval to reveal a secret, and no approval mechanism is available yet",
			ErrDeniedByPolicy, record.ID)
	default:
		return fmt.Errorf("%w: %s may not reveal secrets", ErrDeniedByPolicy, record.ID)
	}
}

func defaultPolicy(kind string) Policy {
	if kind == "cli" {
		return Policy{Reveal: RevealAlways}
	}
	return Policy{Reveal: RevealPrompt, Methods: browserMethods}
}

func (r *Registry) expirePendingLocked() {
	now := time.Now()
	for code, p := range r.pending {
		if now.After(p.expires) {
			delete(r.pending, code)
		}
	}
}

func (r *Registry) expireNoncesLocked() {
	cutoff := time.Now().Add(-replayWindow)
	for nonce, seen := range r.nonces {
		if seen.Before(cutoff) {
			delete(r.nonces, nonce)
		}
	}
}

func (r *Registry) saveLocked() error {
	records := make([]*ClientRecord, 0, len(r.clients))
	for _, c := range r.clients {
		records = append(records, c)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].ID < records[j].ID })

	data, err := json.MarshalIndent(struct {
		Clients []*ClientRecord `json:"clients"`
	}{records}, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(r.path), 0700); err != nil {
		return err
	}
	return os.WriteFile(r.path, data, 0600)
}

func pairingCode() (string, error) {
	var digits [8]byte
	for i := range digits {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		digits[i] = byte('0' + n.Int64())
	}
	return string(digits[:4]) + "-" + string(digits[4:]), nil
}
