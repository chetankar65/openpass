package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/chetankar/openpass/internal/crypto"
	"github.com/chetankar/openpass/internal/vault"
)

/*
Code	Meaning	Client should
-32700/-32600/-32601/-32602	Standard JSON-RPC parse/request/method/params errors	Fix the call
-32001	VAULT_LOCKED	Prompt the user to unlock
-32002	BAD_PASSWORD	Re-prompt; respect the backoff
-32003	NOT_FOUND
-32004	AMBIGUOUS — a name matched more than one entry	Disambiguate by id
-32005	NOT_PAIRED	Run the pairing flow
-32006	DENIED_BY_POLICY	Tell the user; do not retry in a loop
-32007	USER_REJECTED — approval prompt declined	Give up quietly
-32008	VAULT_EXISTS / NO_VAULT
-32009	STORAGE — I/O or integrity failure	Surface loudly; may indicate tampering
*/

const (
	codeInvalidParams = -32602
	codeMethodUnknown = -32601
	codeVaultLocked   = -32001
	codeBadPassword   = -32002
	codeNotFound      = -32003
	codeVaultExists   = -32008
	codeStorage       = -32009
)

// ErrLocked is returned by session operations that need an unlocked vault.
var ErrLocked = errors.New("vault is locked")

// rpcError carries a JSON-RPC error code alongside the message.
type rpcError struct {
	Code    int
	Message string
}

func (e *rpcError) Error() string { return e.Message }

func errf(code int, format string, args ...any) *rpcError {
	return &rpcError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// toRPCError maps an internal error onto the wire codes.
//
// The distinction that matters: a failed unwrap is a wrong password, but a
// failed body decrypt means the file was modified by someone who knew the
// password was right. Collapsing them would send the user hunting for a typo.
func toRPCError(err error) *rpcError {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrLocked):
		return errf(codeVaultLocked, "vault is locked")
	case errors.Is(err, vault.ErrBadPassword):
		return errf(codeBadPassword, "incorrect master password")
	case errors.Is(err, vault.ErrVaultExists):
		return errf(codeVaultExists, "%v", err)
	case errors.Is(err, vault.ErrStorage),
		errors.Is(err, vault.ErrConcurrentModification):
		return errf(codeStorage, "%v", err)
	default:
		return errf(codeStorage, "%v", err)
	}
}

// ---- parameter shapes -------------------------------------------------------

type passwordParams struct {
	Password string `json:"password"`
}

type matchParams struct {
	URL           string `json:"url"`
	AllowInsecure bool   `json:"allow_insecure"`
}

type getParams struct {
	ID     string `json:"id"`
	Reveal bool   `json:"reveal"`
}

type addParams struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	URLs     []string `json:"urls"`
	Notes    string   `json:"notes"`
	Tags     []string `json:"tags"`
}

type updateParams struct {
	ID    string    `json:"id"`
	Entry addParams `json:"entry"`
}

type idParams struct {
	ID string `json:"id"`
}

func decodeParams(raw json.RawMessage, into any) *rpcError {
	if len(raw) == 0 {
		return errf(codeInvalidParams, "missing params")
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return errf(codeInvalidParams, "invalid params: %v", err)
	}
	return nil
}

// ---- response shapes --------------------------------------------------------

// entryView is the wire representation of an entry. It is a separate type from
// vault.Entry on purpose: vault.Entry holds live crypto.Secret values, and
// marshalling one straight onto the socket would put a password on the wire
// whether or not the caller asked to reveal it.
type entryView struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	URLs     []string `json:"urls,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`

	// Password is only ever populated for vault.get with reveal: true.
	Password string `json:"password,omitempty"`
}

func viewOf(e vault.Entry, reveal bool) entryView {
	view := entryView{
		ID:       e.ID,
		Name:     e.Name,
		Username: e.Username,
		URLs:     e.URLs,
		Tags:     e.Tags,
		Notes:    e.Notes,
	}
	if reveal {
		view.Password = string(e.Secret.GetSecret())
	}
	return view
}

// ---- handlers ---------------------------------------------------------------

// handleStatus deliberately does not touch the autolock timer: polling status
// must not keep the vault open.
func (s *Session) handleStatus() (any, *rpcError) {
	return map[string]any{
		"vault_present": s.HasVault(),
		"locked":        !s.IsUnlocked(),
		"entry_count":   nullableCount(s.EntryCount()),
		"locks_in":      nullableSeconds(s.LocksIn()),
	}, nil
}

// nullableSeconds renders a negative duration as null, which is what both a
// locked vault and disabled autolock report.
func nullableSeconds(d time.Duration) any {
	if d < 0 {
		return nil
	}
	return int(d.Seconds())
}

// nullableCount reports null rather than 0 when locked: a locked vault leaks
// nothing about its contents, not even how many entries it holds.
func nullableCount(n int) any {
	if n < 0 {
		return nil
	}
	return n
}

func (s *Session) handleInit(raw json.RawMessage) (any, *rpcError) {
	var p passwordParams
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	password := []byte(p.Password)
	defer crypto.Zero(password)

	if err := s.Init(password); err != nil {
		return nil, toRPCError(err)
	}
	return map[string]any{"locked": false}, nil
}

func (s *Session) handleUnlock(raw json.RawMessage) (any, *rpcError) {
	var p passwordParams
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	password := []byte(p.Password)
	defer crypto.Zero(password)

	if err := s.Unlock(password); err != nil {
		return nil, toRPCError(err)
	}
	return map[string]any{"locked": false, "entry_count": s.EntryCount()}, nil
}

func (s *Session) handleLock() (any, *rpcError) {
	s.Lock()
	return map[string]any{"locked": true}, nil
}

// handleList never reveals secrets. Clients use this for anything they display.
func (s *Session) handleList() (any, *rpcError) {
	var views []entryView

	err := s.withVault(func(v *vault.Vault) (bool, error) {
		for _, e := range v.Body {
			views = append(views, viewOf(e, false))
		}
		return false, nil
	})
	if err != nil {
		return nil, toRPCError(err)
	}

	if views == nil {
		views = []entryView{}
	}
	return map[string]any{"entries": views}, nil
}

// handleMatch answers "do I have a login for this page?" without revealing
// anything. The daemon owns the matching so no client can invent its own.
func (s *Session) handleMatch(raw json.RawMessage) (any, *rpcError) {
	var p matchParams
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	var domain string
	var views []entryView

	err := s.withVault(func(v *vault.Vault) (bool, error) {
		d, matched, err := vault.MatchURL(v.Body, p.URL, vault.MatchOptions{AllowInsecure: p.AllowInsecure})
		if err != nil {
			return false, err
		}
		domain = d
		for _, e := range matched {
			views = append(views, viewOf(e, false))
		}
		return false, nil
	})
	if err != nil {
		if errors.Is(err, vault.ErrUnmatchableURL) {
			return nil, errf(codeInvalidParams, "%v", err)
		}
		return nil, toRPCError(err)
	}

	if views == nil {
		views = []entryView{}
	}
	return map[string]any{"domain": domain, "entries": views}, nil
}

func (s *Session) handleGet(raw json.RawMessage) (any, *rpcError) {
	var p getParams
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	var found *entryView
	err := s.withVault(func(v *vault.Vault) (bool, error) {
		for _, e := range v.Body {
			if e.ID == p.ID {
				view := viewOf(e, p.Reveal)
				found = &view
				return false, nil
			}
		}
		return false, nil
	})
	if err != nil {
		return nil, toRPCError(err)
	}
	if found == nil {
		return nil, errf(codeNotFound, "no entry with id %q", p.ID)
	}
	return map[string]any{"entry": found}, nil
}

func (s *Session) handleAdd(raw json.RawMessage) (any, *rpcError) {
	var p addParams
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}
	if p.Name == "" {
		return nil, errf(codeInvalidParams, "name is required")
	}

	id := p.ID
	if id == "" {
		id = newID()
	}

	err := s.withVault(func(v *vault.Vault) (bool, error) {
		v.AddEntry(vault.Entry{
			ID:       id,
			Name:     p.Name,
			Username: p.Username,
			Secret:   *crypto.SetSecret([]byte(p.Password)),
			URLs:     p.URLs,
			Notes:    p.Notes,
			Tags:     p.Tags,
		})
		return true, nil
	})
	if err != nil {
		return nil, toRPCError(err)
	}
	return map[string]any{"id": id}, nil
}

func (s *Session) handleUpdate(raw json.RawMessage) (any, *rpcError) {
	var p updateParams
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	updated := false
	err := s.withVault(func(v *vault.Vault) (bool, error) {
		for i := range v.Body {
			if v.Body[i].ID != p.ID {
				continue
			}
			e := &v.Body[i]
			if p.Entry.Name != "" {
				e.Name = p.Entry.Name
			}
			if p.Entry.Username != "" {
				e.Username = p.Entry.Username
			}
			if p.Entry.Password != "" {
				e.Secret.ClearSecret()
				e.Secret = *crypto.SetSecret([]byte(p.Entry.Password))
			}
			if p.Entry.URLs != nil {
				e.URLs = p.Entry.URLs
			}
			if p.Entry.Tags != nil {
				e.Tags = p.Entry.Tags
			}
			if p.Entry.Notes != "" {
				e.Notes = p.Entry.Notes
			}
			updated = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, toRPCError(err)
	}
	if !updated {
		return nil, errf(codeNotFound, "no entry with id %q", p.ID)
	}
	return map[string]any{"id": p.ID}, nil
}

func (s *Session) handleDelete(raw json.RawMessage) (any, *rpcError) {
	var p idParams
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	deleted := false
	err := s.withVault(func(v *vault.Vault) (bool, error) {
		for i := range v.Body {
			if v.Body[i].ID != p.ID {
				continue
			}
			v.Body[i].Secret.ClearSecret()
			v.Body = append(v.Body[:i], v.Body[i+1:]...)
			deleted = true
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return nil, toRPCError(err)
	}
	if !deleted {
		return nil, errf(codeNotFound, "no entry with id %q", p.ID)
	}
	return map[string]any{"deleted": true}, nil
}

// Dispatch routes one request to its handler.
func (s *Session) Dispatch(req RequestData) (any, *rpcError) {
	switch req.Method {
	case "status":
		return s.handleStatus()
	case "vault.init":
		return s.handleInit(req.Params)
	case "unlock":
		return s.handleUnlock(req.Params)
	case "lock":
		return s.handleLock()
	case "vault.list":
		return s.handleList()
	case "vault.match":
		return s.handleMatch(req.Params)
	case "vault.get":
		return s.handleGet(req.Params)
	case "vault.add":
		return s.handleAdd(req.Params)
	case "vault.update":
		return s.handleUpdate(req.Params)
	case "vault.delete":
		return s.handleDelete(req.Params)
	default:
		return nil, errf(codeMethodUnknown, "unknown method %q", req.Method)
	}
}
