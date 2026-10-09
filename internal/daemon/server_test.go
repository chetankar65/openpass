package daemon

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/chetankar/openpass/internal/client"
)

const serverTestPassword = "correct-horse-battery-staple"

// startServer runs a daemon on a temporary socket and vault.
func startServer(t *testing.T) (*Server, string) {
	t.Helper()

	dir := t.TempDir()

	// The socket lives in a short path of its own: sun_path is capped at 104
	// bytes and t.TempDir embeds the test name.
	sockDir, err := os.MkdirTemp("", "op")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })

	s, err := NewServer(filepath.Join(sockDir, "d.sock"), filepath.Join(dir, "vault.opv"), DefaultIdleTimeout)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	go s.Serve()
	return s, dir
}

// dialAs connects with a fresh identity and registers it.
func dialAs(t *testing.T, s *Server, dir, name, kind string) (*client.Client, client.PairResult) {
	t.Helper()

	identity, err := client.LoadOrCreateIdentity(filepath.Join(dir, name+".key"), name, kind)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity failed: %v", err)
	}

	c, err := client.Dial(s.Addr())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetIdentity(identity)

	result, err := c.Pair()
	if err != nil {
		t.Fatalf("Pair failed: %v", err)
	}
	return c, result
}

func TestServerLifecycle(t *testing.T) {
	s, dir := startServer(t)
	c, pair := dialAs(t, s, dir, "cli", "cli")

	if pair.State != StateApproved {
		t.Fatalf("the first client is %s, want approved", pair.State)
	}

	status, err := c.Status()
	if err != nil {
		t.Fatalf("status failed: %v", err)
	}
	if status.VaultPresent || !status.Locked {
		t.Errorf("fresh status = %+v, want absent and locked", status)
	}
	if status.EntryCount != nil {
		t.Error("entry_count is reported while locked")
	}

	if _, err := c.List(); !client.IsCode(err, client.CodeVaultLocked) {
		t.Errorf("list while locked err = %v, want VAULT_LOCKED", err)
	}

	if err := c.Init([]byte(serverTestPassword)); err != nil {
		t.Fatalf("init failed: %v", err)
	}

	id, err := c.Add(client.AddParams{
		Name: "GitHub", Username: "chetan", Password: "hunter2",
		URLs: []string{"https://github.com"},
	})
	if err != nil {
		t.Fatalf("add failed: %v", err)
	}

	entries, err := c.List()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(entries) != 1 || entries[0].Password != "" {
		t.Errorf("list returned %+v; it must never carry a password", entries)
	}

	if entry, err := c.Get(id, false); err != nil || entry.Password != "" {
		t.Errorf("get without reveal returned a password: %+v (%v)", entry, err)
	}

	entry, err := c.Get(id, true)
	if err != nil {
		t.Fatalf("get with reveal failed: %v", err)
	}
	if entry.Password != "hunter2" {
		t.Errorf("revealed password = %q, want hunter2", entry.Password)
	}

	if err := c.Lock(); err != nil {
		t.Fatalf("lock failed: %v", err)
	}
	if _, err := c.Get(id, false); !client.IsCode(err, client.CodeVaultLocked) {
		t.Errorf("get after lock err = %v, want VAULT_LOCKED", err)
	}

	if err := c.Unlock([]byte("wrong")); !client.IsCode(err, client.CodeBadPassword) {
		t.Errorf("wrong password err = %v, want BAD_PASSWORD", err)
	}
	if err := c.Unlock([]byte(serverTestPassword)); err != nil {
		t.Fatalf("unlock failed: %v", err)
	}

	if entry, err := c.Get(id, true); err != nil || entry.Password != "hunter2" {
		t.Errorf("password did not survive the reload: %+v (%v)", entry, err)
	}

	if err := c.Delete(id); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if _, err := c.Get(id, false); !client.IsCode(err, client.CodeNotFound) {
		t.Errorf("get after delete err = %v, want NOT_FOUND", err)
	}
}

// Unsigned requests must be rejected, and must not take the daemon down.
func TestServerRejectsUnsignedRequests(t *testing.T) {
	s, dir := startServer(t)

	conn, err := net.Dial("unix", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	send := func(method string, params any) ResponseData {
		t.Helper()
		req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
		if params != nil {
			req["params"] = params
		}
		if err := enc.Encode(req); err != nil {
			t.Fatal(err)
		}
		var resp ResponseData
		if err := dec.Decode(&resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}

	for _, method := range []string{"status", "vault.list", "vault.init", "client.list"} {
		resp := send(method, map[string]any{"password": "x"})
		if resp.Error == nil {
			t.Errorf("unsigned %s succeeded", method)
			continue
		}
		if resp.Error.Code != codeNotPaired {
			t.Errorf("unsigned %s code = %d, want %d", method, resp.Error.Code, codeNotPaired)
		}
	}

	// Still serving.
	c, _ := dialAs(t, s, dir, "cli", "cli")
	if _, err := c.Status(); err != nil {
		t.Fatalf("the daemon stopped serving: %v", err)
	}
}

func TestServerSurvivesBadRequests(t *testing.T) {
	s, dir := startServer(t)
	c, _ := dialAs(t, s, dir, "cli", "cli")

	if err := c.Init([]byte(serverTestPassword)); err != nil {
		t.Fatal(err)
	}

	if _, err := c.Get("no-such-id", false); !client.IsCode(err, client.CodeNotFound) {
		t.Errorf("err = %v, want NOT_FOUND", err)
	}
	if _, err := c.Add(client.AddParams{}); err == nil {
		t.Error("add accepted an entry with no name")
	}

	if _, err := c.Status(); err != nil {
		t.Fatalf("the daemon stopped serving after bad requests: %v", err)
	}
}

// shortSocketPath returns a socket path under the 104-byte sun_path limit;
// t.TempDir embeds the test name and routinely exceeds it.
func shortSocketPath(t *testing.T) string {
	t.Helper()

	dir, err := os.MkdirTemp("", "op")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "d.sock")
}
