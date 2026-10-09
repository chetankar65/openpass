package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const approvalTTL = 30 * time.Second

var (
	ErrNoWatcher     = errors.New("no approver is listening")
	ErrUserRejected  = errors.New("the request was declined")
	ErrApprovalStale = errors.New("the request timed out waiting for approval")
)

// ApprovalRequest is what a watcher is asked to decide.
type ApprovalRequest struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	Client   string `json:"client"`
	Entry    string `json:"entry"`
	Domain   string `json:"domain,omitempty"`
	Expires  int64  `json:"expires"`
}

type pendingApproval struct {
	request ApprovalRequest
	answer  chan bool
}

// Broker parks requests that need a human and routes the question to whoever
// is watching.
//
// Everything fails closed: no watcher, no answer in time, or a watcher that
// disconnects all deny.
type Broker struct {
	mu       sync.Mutex
	watchers map[int]chan ApprovalRequest
	pending  map[string]*pendingApproval
	nextID   int
	grants   map[string]time.Time
}

func NewBroker() *Broker {
	return &Broker{
		watchers: map[int]chan ApprovalRequest{},
		pending:  map[string]*pendingApproval{},
		grants:   map[string]time.Time{},
	}
}

// Subscribe registers a watcher. The returned function unregisters it.
func (b *Broker) Subscribe() (<-chan ApprovalRequest, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.nextID++
	id := b.nextID
	ch := make(chan ApprovalRequest, 8)
	b.watchers[id] = ch

	return ch, func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		if existing, ok := b.watchers[id]; ok {
			delete(b.watchers, id)
			close(existing)
		}
	}
}

func (b *Broker) HasWatcher() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.watchers) > 0
}

// Ask blocks until a watcher answers, the request times out, or it is refused
// outright because nobody is listening.
func (b *Broker) Ask(req ApprovalRequest) error {
	return b.askWithTimeout(req, approvalTTL)
}

func (b *Broker) askWithTimeout(req ApprovalRequest, timeout time.Duration) error {
	b.mu.Lock()

	if len(b.watchers) == 0 {
		b.mu.Unlock()
		return ErrNoWatcher
	}

	// A live grant for this client and domain skips the question, so a burst of
	// fills does not become a burst of prompts.
	if until, ok := b.grants[grantKey(req.ClientID, req.Domain)]; ok && time.Now().Before(until) {
		b.mu.Unlock()
		return nil
	}

	id, err := approvalID()
	if err != nil {
		b.mu.Unlock()
		return err
	}
	req.ID = id
	req.Expires = time.Now().Add(timeout).Unix()

	p := &pendingApproval{request: req, answer: make(chan bool, 1)}
	b.pending[id] = p

	for _, ch := range b.watchers {
		select {
		case ch <- req:
		default:
		}
	}
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.pending, id)
		b.mu.Unlock()
	}()

	select {
	case allowed := <-p.answer:
		if !allowed {
			return ErrUserRejected
		}
		return nil
	case <-time.After(timeout):
		return ErrApprovalStale
	}
}

// Respond answers a parked request. ttl, if positive, grants the same client
// and domain a pass for that long.
func (b *Broker) Respond(id string, allow bool, ttl time.Duration) error {
	b.mu.Lock()

	p, ok := b.pending[id]
	if !ok {
		b.mu.Unlock()
		return errors.New("no request is waiting with that id")
	}
	if allow && ttl > 0 {
		b.grants[grantKey(p.request.ClientID, p.request.Domain)] = time.Now().Add(ttl)
	}
	b.mu.Unlock()

	select {
	case p.answer <- allow:
	default:
	}
	return nil
}

// Pending lists the requests currently waiting, so a watcher that connects
// late can still see them.
func (b *Broker) Pending() []ApprovalRequest {
	b.mu.Lock()
	defer b.mu.Unlock()

	out := make([]ApprovalRequest, 0, len(b.pending))
	for _, p := range b.pending {
		out = append(out, p.request)
	}
	return out
}

// RevokeGrants drops any standing permissions, used when the vault locks.
func (b *Broker) RevokeGrants() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.grants = map[string]time.Time{}
}

func grantKey(clientID, domain string) string { return clientID + "\x00" + domain }

func approvalID() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
