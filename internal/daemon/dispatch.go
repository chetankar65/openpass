package daemon

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/chetankar/openpass/internal/vault"
)

const (
	codeNotPaired      = -32005
	codeDeniedByPolicy = -32006
	codeUserRejected   = -32007
)

// dispatch authenticates a request, then routes it.
//
// client.pair is the only unauthenticated method, because a client cannot sign
// before it has registered. Everything else must be signed: if unsigned
// requests were accepted at all, every policy below would be bypassable by
// simply omitting the signature.
func (s *Server) dispatch(req RequestData) (any, *rpcError) {
	if req.Method == "client.pair" {
		return s.handlePair(req.Params)
	}

	record, err := s.registry.Verify(req.Auth, req.Method, req.Params)
	if err != nil {
		if errors.Is(err, ErrNotPaired) {
			return nil, errf(codeNotPaired, "%v", err)
		}
		return nil, errf(codeNotPaired, "authentication failed: %v", err)
	}

	if !record.Policy.Allows(req.Method) {
		return nil, errf(codeDeniedByPolicy, "%s may not call %s", record.ID, req.Method)
	}

	switch req.Method {
	case "events.subscribe":
		return map[string]any{"subscribed": true}, nil
	case "client.respond":
		return s.handleRespond(req.Params)
	case "client.list":
		return map[string]any{"clients": s.registry.List()}, nil
	case "client.approve":
		return s.handleApprove(req.Params)
	case "client.revoke":
		return s.handleRevoke(req.Params)
	}

	// Revealing a secret is the one call policy gates.
	if req.Method == "vault.get" && wantsReveal(req.Params) {
		if rerr := s.authorizeReveal(record, req.Params); rerr != nil {
			return nil, rerr
		}
	}

	return s.session.Dispatch(req)
}

// authorizeReveal applies the client's reveal policy, asking a human when the
// policy says to.
func (s *Server) authorizeReveal(record *ClientRecord, params json.RawMessage) *rpcError {
	switch record.Policy.Reveal {
	case RevealAlways:
		return nil
	case RevealPrompt:
		// fall through to the prompt
	default:
		return errf(codeDeniedByPolicy, "%s may not reveal secrets", record.ID)
	}

	name, domain := s.describeTarget(params)

	err := s.broker.Ask(ApprovalRequest{
		ClientID: record.ID,
		Client:   record.Name,
		Entry:    name,
		Domain:   domain,
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNoWatcher):
		return errf(codeDeniedByPolicy,
			"%s needs approval to reveal a secret, but nothing is listening; run `openpass watch`", record.ID)
	case errors.Is(err, ErrUserRejected):
		return errf(codeUserRejected, "the request was declined")
	default:
		return errf(codeUserRejected, "%v", err)
	}
}

// describeTarget looks up what the request is actually for, so the human is
// asked about a name rather than an opaque id.
func (s *Server) describeTarget(params json.RawMessage) (name, domain string) {
	var p struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return "", ""
	}

	_ = s.session.withVault(func(v *vault.Vault) (bool, error) {
		for _, e := range v.Body {
			if e.ID == p.ID {
				name = e.Name
				if len(e.URLs) > 0 {
					if d, err := vault.RegistrableDomain(e.URLs[0]); err == nil {
						domain = d
					}
				}
				return false, nil
			}
		}
		return false, nil
	})
	return name, domain
}

func (s *Server) handleRespond(raw json.RawMessage) (any, *rpcError) {
	var p struct {
		ID         string `json:"id"`
		Allow      bool   `json:"allow"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	if err := s.broker.Respond(p.ID, p.Allow, time.Duration(p.TTLSeconds)*time.Second); err != nil {
		return nil, errf(codeNotFound, "%v", err)
	}
	return map[string]any{"ok": true}, nil
}

func wantsReveal(params json.RawMessage) bool {
	var p struct {
		Reveal bool `json:"reveal"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Reveal
}

func (s *Server) handlePair(raw json.RawMessage) (any, *rpcError) {
	var p struct {
		Name   string `json:"name"`
		Kind   string `json:"kind"`
		PubKey []byte `json:"pubkey"`
	}
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	record, code, err := s.registry.Pair(p.Name, p.Kind, ed25519.PublicKey(p.PubKey))
	if err != nil {
		return nil, errf(codeInvalidParams, "%v", err)
	}

	out := map[string]any{"client_id": record.ID, "state": record.State}
	if code != "" {
		out["code"] = code
	}
	return out, nil
}

func (s *Server) handleApprove(raw json.RawMessage) (any, *rpcError) {
	var p struct {
		Code string `json:"code"`
	}
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	record, err := s.registry.Approve(p.Code)
	if err != nil {
		return nil, errf(codeNotFound, "%v", err)
	}
	return record, nil
}

func (s *Server) handleRevoke(raw json.RawMessage) (any, *rpcError) {
	var p struct {
		ID string `json:"id"`
	}
	if rerr := decodeParams(raw, &p); rerr != nil {
		return nil, rerr
	}

	if err := s.registry.Revoke(p.ID); err != nil {
		return nil, errf(codeNotFound, "%v", err)
	}
	return map[string]any{"revoked": true}, nil
}
