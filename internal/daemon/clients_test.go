package daemon

import (
	"path/filepath"
	"testing"

	"github.com/chetankar/openpass/internal/client"
)

// The first client self-approves to break the bootstrap; every later one waits.
func TestPairFirstClientIsApprovedAndSecondIsNot(t *testing.T) {
	s, dir := startServer(t)

	_, first := dialAs(t, s, dir, "cli", "cli")
	if first.State != StateApproved {
		t.Errorf("first client state = %s, want approved", first.State)
	}
	if first.Code != "" {
		t.Error("first client was given a pairing code it does not need")
	}

	_, second := dialAs(t, s, dir, "ext", "browser")
	if second.State != StatePending {
		t.Errorf("second client state = %s, want pending", second.State)
	}
	if second.Code == "" {
		t.Error("second client got no pairing code")
	}
}

// A pending client can do nothing until a human approves it.
func TestPendingClientIsRefused(t *testing.T) {
	s, dir := startServer(t)

	cli, _ := dialAs(t, s, dir, "cli", "cli")
	if err := cli.Init([]byte(serverTestPassword)); err != nil {
		t.Fatal(err)
	}

	ext, pair := dialAs(t, s, dir, "ext", "browser")
	if _, err := ext.List(); !client.IsCode(err, -32005) {
		t.Fatalf("pending client list err = %v, want NOT_PAIRED", err)
	}

	if _, err := cli.ApproveClient(pair.Code); err != nil {
		t.Fatalf("approve failed: %v", err)
	}

	if _, err := ext.List(); err != nil {
		t.Errorf("approved client still refused: %v", err)
	}
}

// Approval grants access, not permission to read secrets. A browser client
// defaults to prompt, and with no way to ask a human that must deny.
func TestApprovedBrowserStillCannotReveal(t *testing.T) {
	s, dir := startServer(t)

	cli, _ := dialAs(t, s, dir, "cli", "cli")
	if err := cli.Init([]byte(serverTestPassword)); err != nil {
		t.Fatal(err)
	}
	id, err := cli.Add(client.AddParams{Name: "GitHub", Password: "hunter2"})
	if err != nil {
		t.Fatal(err)
	}

	ext, pair := dialAs(t, s, dir, "ext", "browser")
	if _, err := cli.ApproveClient(pair.Code); err != nil {
		t.Fatal(err)
	}

	// Metadata is fine.
	if _, err := ext.Get(id, false); err != nil {
		t.Errorf("approved browser cannot read metadata: %v", err)
	}

	// The secret is not.
	if _, err := ext.Get(id, true); !client.IsCode(err, -32006) {
		t.Errorf("reveal err = %v, want DENIED_BY_POLICY", err)
	}

	// The CLI can, because its default policy is always.
	if entry, err := cli.Get(id, true); err != nil || entry.Password != "hunter2" {
		t.Errorf("cli reveal failed: %+v (%v)", entry, err)
	}
}

func TestApproveRejectsUnknownCode(t *testing.T) {
	s, dir := startServer(t)
	cli, _ := dialAs(t, s, dir, "cli", "cli")

	if _, err := cli.ApproveClient("0000-0000"); err == nil {
		t.Error("approve accepted an unknown code")
	}
}

func TestRevokeRemovesAccess(t *testing.T) {
	s, dir := startServer(t)

	cli, _ := dialAs(t, s, dir, "cli", "cli")
	if err := cli.Init([]byte(serverTestPassword)); err != nil {
		t.Fatal(err)
	}

	ext, pair := dialAs(t, s, dir, "ext", "browser")
	if _, err := cli.ApproveClient(pair.Code); err != nil {
		t.Fatal(err)
	}
	if _, err := ext.List(); err != nil {
		t.Fatalf("approved client refused: %v", err)
	}

	if err := cli.RevokeClient(pair.ClientID); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if _, err := ext.List(); !client.IsCode(err, -32005) {
		t.Errorf("revoked client err = %v, want NOT_PAIRED", err)
	}
}

// A replayed request must be refused even though its signature is valid.
func TestNonceCannotBeReplayed(t *testing.T) {
	s, dir := startServer(t)
	cli, _ := dialAs(t, s, dir, "cli", "cli")

	identity, err := client.LoadOrCreateIdentity(filepath.Join(dir, "cli.key"), "cli", "cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.Status(); err != nil {
		t.Fatal(err)
	}

	auth, err := identity.Sign("status", nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.registry.Verify(auth, "status", nil); err != nil {
		t.Fatalf("first use of the nonce failed: %v", err)
	}
	if _, err := s.registry.Verify(auth, "status", nil); err == nil {
		t.Error("the same nonce was accepted twice")
	}
}

// A signature over different params must not verify.
func TestSignatureCoversParams(t *testing.T) {
	s, dir := startServer(t)
	dialAs(t, s, dir, "cli", "cli")

	identity, err := client.LoadOrCreateIdentity(filepath.Join(dir, "cli.key"), "cli", "cli")
	if err != nil {
		t.Fatal(err)
	}

	auth, err := identity.Sign("vault.get", []byte(`{"id":"a","reveal":false}`))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.registry.Verify(auth, "vault.get", []byte(`{"id":"a","reveal":true}`)); err == nil {
		t.Error("a signature verified against tampered params")
	}
}

// The registry must survive a daemon restart.
func TestRegistryPersists(t *testing.T) {
	s, dir := startServer(t)

	cli, _ := dialAs(t, s, dir, "cli", "cli")
	_, pair := dialAs(t, s, dir, "ext", "browser")
	if _, err := cli.ApproveClient(pair.Code); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewRegistry(filepath.Join(dir, "clients.json"))
	if err != nil {
		t.Fatalf("NewRegistry failed: %v", err)
	}

	var found bool
	for _, r := range reloaded.List() {
		if r.ID == pair.ClientID && r.State == StateApproved {
			found = true
		}
	}
	if !found {
		t.Error("the approved client did not survive a reload")
	}
}

// Pairing again before approval must not create a second pending record: the
// CLI registers on every invocation, so this happens constantly.
func TestPairIsIdempotentWhilePending(t *testing.T) {
	s, dir := startServer(t)
	dialAs(t, s, dir, "cli", "cli")

	_, first := dialAs(t, s, dir, "ext", "browser")
	_, second := dialAs(t, s, dir, "ext", "browser")

	if first.Code != second.Code {
		t.Errorf("a second pair gave a new code: %q then %q", first.Code, second.Code)
	}

	pending := 0
	for _, r := range s.registry.List() {
		if r.State == StatePending {
			pending++
		}
	}
	if pending != 1 {
		t.Errorf("%d pending records, want 1", pending)
	}
}

// A browser client may read, but must not be able to delete or manage clients.
func TestBrowserPolicyRestrictsMethods(t *testing.T) {
	s, dir := startServer(t)

	cli, _ := dialAs(t, s, dir, "cli", "cli")
	if err := cli.Init([]byte(serverTestPassword)); err != nil {
		t.Fatal(err)
	}
	id, err := cli.Add(client.AddParams{Name: "GitHub", Password: "hunter2", URLs: []string{"https://github.com"}})
	if err != nil {
		t.Fatal(err)
	}

	ext, pair := dialAs(t, s, dir, "ext", "browser")
	if _, err := cli.ApproveClient(pair.Code); err != nil {
		t.Fatal(err)
	}

	for _, allowed := range []func() error{
		func() error { _, err := ext.Status(); return err },
		func() error { _, err := ext.List(); return err },
		func() error { _, err := ext.Get(id, false); return err },
		func() error { _, err := ext.Match("https://github.com", false); return err },
	} {
		if err := allowed(); err != nil {
			t.Errorf("a permitted call was refused: %v", err)
		}
	}

	if err := ext.Delete(id); !client.IsCode(err, -32006) {
		t.Errorf("delete err = %v, want DENIED_BY_POLICY", err)
	}
	if _, err := ext.Add(client.AddParams{Name: "x", Password: "y"}); !client.IsCode(err, -32006) {
		t.Errorf("add err = %v, want DENIED_BY_POLICY", err)
	}
	if err := ext.RevokeClient("cli-anything"); !client.IsCode(err, -32006) {
		t.Errorf("revoke err = %v, want DENIED_BY_POLICY", err)
	}
	if err := ext.Lock(); !client.IsCode(err, -32006) {
		t.Errorf("lock err = %v, want DENIED_BY_POLICY", err)
	}
}
