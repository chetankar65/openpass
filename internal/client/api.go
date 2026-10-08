package client

import (
	"errors"
	"fmt"
	"strings"
)

// Status is the daemon's view of itself. EntryCount and LocksIn are nil while
// locked — a locked vault reports nothing about its contents.
type Status struct {
	VaultPresent bool `json:"vault_present"`
	Locked       bool `json:"locked"`
	EntryCount   *int `json:"entry_count"`
	LocksIn      *int `json:"locks_in"`
}

// Entry is the wire shape of a vault entry. Password is populated only by Get
// with reveal set.
type Entry struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Username string   `json:"username"`
	URLs     []string `json:"urls,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
	Password string   `json:"password,omitempty"`
}

// AddParams describes a new entry.
type AddParams struct {
	Name     string   `json:"name"`
	Username string   `json:"username,omitempty"`
	Password string   `json:"password,omitempty"`
	URLs     []string `json:"urls,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Notes    string   `json:"notes,omitempty"`
}

func (c *Client) Status() (Status, error) {
	var s Status
	err := c.call("status", nil, &s)
	return s, err
}

func (c *Client) Init(password []byte) error {
	return c.call("vault.init", map[string]any{"password": string(password)}, nil)
}

func (c *Client) Unlock(password []byte) error {
	return c.call("unlock", map[string]any{"password": string(password)}, nil)
}

func (c *Client) Lock() error {
	return c.call("lock", nil, nil)
}

// List returns every entry without secrets.
func (c *Client) List() ([]Entry, error) {
	var out struct {
		Entries []Entry `json:"entries"`
	}
	err := c.call("vault.list", nil, &out)
	return out.Entries, err
}

// Get fetches one entry by id. reveal must be true to receive the password,
// which is the call the daemon treats as the policy checkpoint.
func (c *Client) Get(id string, reveal bool) (Entry, error) {
	var out struct {
		Entry Entry `json:"entry"`
	}
	err := c.call("vault.get", map[string]any{"id": id, "reveal": reveal}, &out)
	return out.Entry, err
}

func (c *Client) Add(p AddParams) (string, error) {
	var out struct {
		ID string `json:"id"`
	}
	if err := c.call("vault.add", p, &out); err != nil {
		return "", err
	}
	return out.ID, nil
}

func (c *Client) Update(id string, p AddParams) error {
	return c.call("vault.update", map[string]any{"id": id, "entry": p}, nil)
}

func (c *Client) Delete(id string) error {
	return c.call("vault.delete", map[string]any{"id": id}, nil)
}

// AmbiguousError lists the entries a name matched when more than one did.
//
// Resolving a name to the wrong entry means pasting the wrong credential into
// a login form, so an ambiguous name is always an error, never a guess.
type AmbiguousError struct {
	Query   string
	Matches []Entry
}

func (e *AmbiguousError) Error() string {
	return fmt.Sprintf("%q matches %d entries", e.Query, len(e.Matches))
}

// NotFoundError is returned when a name or id matches nothing.
type NotFoundError struct{ Query string }

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("no entry matching %q", e.Query)
}

// Resolve turns a user-typed name or id into a single entry id.
//
// It tries, in order: an exact id, an exact name (case-insensitive), a name
// prefix, then a substring of the name, username or URL. The first tier that
// matches anything decides — so an exact name wins over a longer name that
// merely contains it — and more than one match at that tier is an error.
func (c *Client) Resolve(query string) (string, error) {
	entries, err := c.List()
	if err != nil {
		return "", err
	}
	return resolveIn(entries, query)
}

// resolveIn holds the matching logic, separately from fetching the entries, so
// it can be tested directly rather than through a daemon.
func resolveIn(entries []Entry, query string) (string, error) {
	for _, e := range entries {
		if e.ID == query {
			return e.ID, nil
		}
	}

	tiers := []func(Entry) bool{
		func(e Entry) bool { return equalFold(e.Name, query) },
		func(e Entry) bool { return hasPrefixFold(e.Name, query) },
		func(e Entry) bool {
			if containsFold(e.Name, query) || containsFold(e.Username, query) {
				return true
			}
			for _, u := range e.URLs {
				if containsFold(u, query) {
					return true
				}
			}
			return false
		},
	}

	for _, match := range tiers {
		var hits []Entry
		for _, e := range entries {
			if match(e) {
				hits = append(hits, e)
			}
		}
		switch len(hits) {
		case 0:
			continue
		case 1:
			return hits[0].ID, nil
		default:
			return "", &AmbiguousError{Query: query, Matches: hits}
		}
	}

	return "", &NotFoundError{Query: query}
}

func equalFold(a, b string) bool { return strings.EqualFold(a, b) }
func hasPrefixFold(s, pre string) bool {
	return len(s) >= len(pre) && strings.EqualFold(s[:len(pre)], pre)
}
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

type ClientRecord struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
	Policy struct {
		Reveal string `json:"reveal"`
	} `json:"policy"`
	LastSeen string `json:"last_seen,omitempty"`
}

type PairResult struct {
	ClientID string `json:"client_id"`
	State    string `json:"state"`
	Code     string `json:"code,omitempty"`
}

// Pair registers this client's identity. Unauthenticated by necessity.
func (c *Client) Pair() (PairResult, error) {
	var out PairResult
	if c.identity == nil {
		return out, errors.New("no identity to pair")
	}
	err := c.call("client.pair", map[string]any{
		"name":   c.identity.Name,
		"kind":   c.identity.Kind,
		"pubkey": []byte(c.identity.PublicKey()),
	}, &out)
	return out, err
}

func (c *Client) ListClients() ([]ClientRecord, error) {
	var out struct {
		Clients []ClientRecord `json:"clients"`
	}
	err := c.call("client.list", nil, &out)
	return out.Clients, err
}

func (c *Client) ApproveClient(code string) (ClientRecord, error) {
	var out ClientRecord
	err := c.call("client.approve", map[string]any{"code": code}, &out)
	return out, err
}

func (c *Client) RevokeClient(id string) error {
	return c.call("client.revoke", map[string]any{"id": id}, nil)
}
