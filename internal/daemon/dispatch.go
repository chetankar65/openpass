package daemon

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
)

const codeNotPaired = -32005
const codeDeniedByPolicy = -32006

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

	switch req.Method {
	case "client.list":
		return map[string]any{"clients": s.registry.List()}, nil
	case "client.approve":
		return s.handleApprove(req.Params)
	case "client.revoke":
		return s.handleRevoke(req.Params)
	}

	// Revealing a secret is the one call policy gates.
	if req.Method == "vault.get" && wantsReveal(req.Params) {
		if err := CanReveal(record); err != nil {
			return nil, errf(codeDeniedByPolicy, "%v", err)
		}
	}

	return s.session.Dispatch(req)
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
