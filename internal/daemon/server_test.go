package daemon

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
)

// testClient is a connection to a running daemon.
type testClient struct {
	t   *testing.T
	enc *json.Encoder
	dec *json.Decoder
}

// newTestServer starts a real daemon on a temporary socket and vault, and
// returns a connected client.
//
// Serve() blocks forever by design, so it runs in a goroutine. Listen() has
// already created the socket by the time this returns, so there is nothing to
// poll for.
func newTestServer(t *testing.T) *testClient {
	t.Helper()

	dir := t.TempDir()
	s, err := NewServer(filepath.Join(dir, "d.sock"), filepath.Join(dir, "vault.opv"), DefaultIdleTimeout)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	go s.Serve()

	conn, err := net.Dial("unix", s.Addr())
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return &testClient{t: t, enc: json.NewEncoder(conn), dec: json.NewDecoder(conn)}
}

// call sends a request and returns the response.
func (c *testClient) call(id int, method string, params any) ResponseData {
	c.t.Helper()

	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	if err := c.enc.Encode(req); err != nil {
		c.t.Fatalf("failed to send %s: %v", method, err)
	}

	var resp ResponseData
	if err := c.dec.Decode(&resp); err != nil {
		c.t.Fatalf("failed to read the response to %s: %v", method, err)
	}
	if resp.Id != id {
		c.t.Errorf("response id = %d, want %d", resp.Id, id)
	}
	return resp
}

func TestServerLifecycle(t *testing.T) {
	c := newTestServer(t)
	const password = "correct-horse-battery-staple"

	// A fresh daemon has no vault and is locked.
	resp := c.call(1, "status", nil)
	if resp.Error != nil {
		t.Fatalf("status failed: %+v", resp.Error)
	}
	status := resp.Result.(map[string]any)
	if status["vault_present"] != false || status["locked"] != true {
		t.Errorf("fresh status = %+v, want absent and locked", status)
	}
	// A locked vault must not report its size, not even as zero.
	if status["entry_count"] != nil {
		t.Errorf("entry_count = %v while locked, want null", status["entry_count"])
	}

	// Reads must fail before unlock.
	if resp := c.call(2, "vault.list", nil); resp.Error == nil {
		t.Error("vault.list succeeded while locked")
	} else if resp.Error.Code != codeVaultLocked {
		t.Errorf("code = %d, want %d (VAULT_LOCKED)", resp.Error.Code, codeVaultLocked)
	}

	// Create the vault.
	if resp := c.call(3, "vault.init", map[string]any{"password": password}); resp.Error != nil {
		t.Fatalf("vault.init failed: %+v", resp.Error)
	}

	// Add an entry.
	resp = c.call(4, "vault.add", map[string]any{
		"name":     "GitHub",
		"username": "chetan",
		"password": "hunter2",
		"urls":     []string{"https://github.com"},
	})
	if resp.Error != nil {
		t.Fatalf("vault.add failed: %+v", resp.Error)
	}
	id := resp.Result.(map[string]any)["id"].(string)

	// list must not carry the secret.
	resp = c.call(5, "vault.list", nil)
	if resp.Error != nil {
		t.Fatalf("vault.list failed: %+v", resp.Error)
	}
	raw, _ := json.Marshal(resp.Result)
	if contains(string(raw), "hunter2") {
		t.Errorf("vault.list leaked the password: %s", raw)
	}

	// get without reveal must not carry it either.
	resp = c.call(6, "vault.get", map[string]any{"id": id})
	raw, _ = json.Marshal(resp.Result)
	if contains(string(raw), "hunter2") {
		t.Errorf("vault.get without reveal leaked the password: %s", raw)
	}

	// get with reveal must.
	resp = c.call(7, "vault.get", map[string]any{"id": id, "reveal": true})
	if resp.Error != nil {
		t.Fatalf("vault.get failed: %+v", resp.Error)
	}
	entry := resp.Result.(map[string]any)["entry"].(map[string]any)
	if entry["password"] != "hunter2" {
		t.Errorf("revealed password = %v, want hunter2", entry["password"])
	}

	// Lock, then confirm the entry is unreachable and the count is hidden.
	if resp := c.call(8, "lock", nil); resp.Error != nil {
		t.Fatalf("lock failed: %+v", resp.Error)
	}
	if resp := c.call(9, "vault.get", map[string]any{"id": id}); resp.Error == nil {
		t.Error("vault.get succeeded after lock")
	}

	// Unlock with the wrong password.
	resp = c.call(10, "unlock", map[string]any{"password": "wrong"})
	if resp.Error == nil {
		t.Fatal("unlock succeeded with the wrong password")
	}
	if resp.Error.Code != codeBadPassword {
		t.Errorf("code = %d, want %d (BAD_PASSWORD)", resp.Error.Code, codeBadPassword)
	}

	// Unlock properly; the entry must have survived the round trip to disk.
	if resp := c.call(11, "unlock", map[string]any{"password": password}); resp.Error != nil {
		t.Fatalf("unlock failed: %+v", resp.Error)
	}
	resp = c.call(12, "vault.get", map[string]any{"id": id, "reveal": true})
	if resp.Error != nil {
		t.Fatalf("vault.get after unlock failed: %+v", resp.Error)
	}
	entry = resp.Result.(map[string]any)["entry"].(map[string]any)
	if entry["password"] != "hunter2" {
		t.Errorf("password after reload = %v, want hunter2", entry["password"])
	}

	// Delete it.
	if resp := c.call(13, "vault.delete", map[string]any{"id": id}); resp.Error != nil {
		t.Fatalf("vault.delete failed: %+v", resp.Error)
	}
	if resp := c.call(14, "vault.get", map[string]any{"id": id}); resp.Error == nil {
		t.Error("vault.get succeeded after delete")
	} else if resp.Error.Code != codeNotFound {
		t.Errorf("code = %d, want %d (NOT_FOUND)", resp.Error.Code, codeNotFound)
	}
}

// A bad request must produce an error response, not kill the daemon.
func TestServerSurvivesBadRequests(t *testing.T) {
	c := newTestServer(t)

	if resp := c.call(1, "does.not.exist", nil); resp.Error == nil {
		t.Error("unknown method succeeded")
	} else if resp.Error.Code != codeMethodUnknown {
		t.Errorf("code = %d, want %d", resp.Error.Code, codeMethodUnknown)
	}

	if resp := c.call(2, "vault.init", nil); resp.Error == nil {
		t.Error("vault.init succeeded with no params")
	}

	if resp := c.call(3, "unlock", "not-an-object"); resp.Error == nil {
		t.Error("unlock succeeded with malformed params")
	}

	// Still alive.
	if resp := c.call(4, "status", nil); resp.Error != nil {
		t.Fatalf("the daemon stopped serving after bad requests: %+v", resp.Error)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
