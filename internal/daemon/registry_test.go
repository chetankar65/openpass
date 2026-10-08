package daemon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/chetankar/openpass/internal/client"
)

func newRegistry(t *testing.T) *Registry {
	t.Helper()

	r, err := NewRegistry(filepath.Join(t.TempDir(), "clients.json"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

// signAs builds an auth block by hand so tests can control the timestamp and
// the claimed client id.
func signAs(t *testing.T, id string, priv ed25519.PrivateKey, method string, params []byte, ts int64) *client.Auth {
	t.Helper()

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	nonce := base64.StdEncoding.EncodeToString(raw)

	sig := ed25519.Sign(priv, client.SigningString(method, params, nonce, ts))
	return &client.Auth{
		ClientID: id,
		Nonce:    nonce,
		TS:       ts,
		Sig:      base64.StdEncoding.EncodeToString(sig),
	}
}

// bootstrap registers a first client so later ones are not auto-approved.
func bootstrap(t *testing.T, r *Registry) {
	t.Helper()

	pub, _ := newKey(t)
	if _, _, err := r.Pair("first", "cli", pub); err != nil {
		t.Fatal(err)
	}
}

// A pairing code must stop working once it expires.
func TestPairingCodeExpires(t *testing.T) {
	r := newRegistry(t)
	bootstrap(t, r)

	pub, _ := newKey(t)
	_, code, err := r.Pair("ext", "browser", pub)
	if err != nil {
		t.Fatal(err)
	}

	r.mu.Lock()
	r.pending[code].expires = time.Now().Add(-time.Second)
	r.mu.Unlock()

	if _, err := r.Approve(code); err == nil {
		t.Error("an expired code was accepted")
	}
}

// An expired pending client must disappear from the listing too, or it looks
// approvable when it is not.
func TestExpiredPendingIsNotListed(t *testing.T) {
	r := newRegistry(t)
	bootstrap(t, r)

	pub, _ := newKey(t)
	_, code, err := r.Pair("ext", "browser", pub)
	if err != nil {
		t.Fatal(err)
	}

	r.mu.Lock()
	r.pending[code].expires = time.Now().Add(-time.Second)
	r.mu.Unlock()

	for _, rec := range r.List() {
		if rec.State == StatePending {
			t.Errorf("an expired pending client is still listed: %s", rec.ID)
		}
	}
}

// A request signed too long ago, or dated into the future, must be refused.
func TestTimestampOutsideWindowIsRejected(t *testing.T) {
	r := newRegistry(t)

	pub, priv := newKey(t)
	record, _, err := r.Pair("cli", "cli", pub)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	cases := map[string]int64{
		"too old":    now - int64(replayWindow.Seconds()) - 5,
		"too future": now + int64(replayWindow.Seconds()) + 5,
	}

	for name, ts := range cases {
		auth := signAs(t, record.ID, priv, "status", nil, ts)
		if _, err := r.Verify(auth, "status", nil); err == nil {
			t.Errorf("%s timestamp was accepted", name)
		}
	}

	// A current timestamp still works, so the test is not passing by accident.
	if _, err := r.Verify(signAs(t, record.ID, priv, "status", nil, now), "status", nil); err != nil {
		t.Errorf("a current timestamp was rejected: %v", err)
	}
}

// Claiming another client's id with your own key must fail: the id and the
// stored public key have to agree.
func TestCannotImpersonateAnotherClient(t *testing.T) {
	r := newRegistry(t)

	victimPub, _ := newKey(t)
	victim, _, err := r.Pair("cli", "cli", victimPub)
	if err != nil {
		t.Fatal(err)
	}

	_, attackerPriv := newKey(t)
	auth := signAs(t, victim.ID, attackerPriv, "status", nil, time.Now().Unix())

	if _, err := r.Verify(auth, "status", nil); err == nil {
		t.Error("a request signed with the wrong key was accepted for another client's id")
	}
}

// A pending client must not be able to approve itself.
func TestPendingClientCannotApproveItself(t *testing.T) {
	s, dir := startServer(t)
	dialAs(t, s, dir, "cli", "cli")

	ext, pair := dialAs(t, s, dir, "ext", "browser")
	if pair.State != StatePending {
		t.Fatalf("second client state = %s, want pending", pair.State)
	}

	if _, err := ext.ApproveClient(pair.Code); err == nil {
		t.Error("a pending client approved itself")
	}

	if _, err := ext.List(); !client.IsCode(err, codeNotPaired) {
		t.Errorf("after self-approval err = %v, want NOT_PAIRED", err)
	}
}

func TestPairRejectsMalformedKey(t *testing.T) {
	r := newRegistry(t)

	if _, _, err := r.Pair("bad", "browser", ed25519.PublicKey("too short")); err == nil {
		t.Error("Pair accepted a malformed public key")
	}
	if _, _, err := r.Pair("", "browser", mustKey(t)); err == nil {
		t.Error("Pair accepted an empty name")
	}
}

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _ := newKey(t)
	return pub
}

// Two clients of different kinds derive different ids from different keys, and
// the same key always derives the same id.
func TestClientIDIsDerivedFromTheKey(t *testing.T) {
	pub, _ := newKey(t)

	if a, b := client.DeriveClientID("cli", pub), client.DeriveClientID("cli", pub); a != b {
		t.Errorf("the same key produced two ids: %s and %s", a, b)
	}

	other, _ := newKey(t)
	if a, b := client.DeriveClientID("cli", pub), client.DeriveClientID("cli", other); a == b {
		t.Error("two different keys produced the same id")
	}
}
