package daemon

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/chetankar/openpass/internal/vault"
)

const testPassword = "correct-horse-battery-staple"

// newSessionWithTimeout gives a session on a throwaway vault, already unlocked.
func newSessionWithTimeout(t *testing.T, timeout time.Duration) *Session {
	t.Helper()

	s, err := NewSession(filepath.Join(t.TempDir(), "vault.opv"), timeout)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	if err := s.Init([]byte(testPassword)); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	return s
}

func TestAutolockFiresWhenIdle(t *testing.T) {
	s := newSessionWithTimeout(t, 60*time.Millisecond)

	if !s.IsUnlocked() {
		t.Fatal("session is locked straight after Init")
	}

	// Wait past the deadline without touching the vault.
	deadline := time.Now().Add(2 * time.Second)
	for s.IsUnlocked() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if s.IsUnlocked() {
		t.Error("the vault did not autolock")
	}
	if got := s.EntryCount(); got != -1 {
		t.Errorf("EntryCount after autolock = %d, want -1", got)
	}
}

// Using the vault must push the deadline back, or a session in active use
// would lock out from under the user mid-task.
func TestAutolockResetsOnUse(t *testing.T) {
	s := newSessionWithTimeout(t, 150*time.Millisecond)

	// Keep it busy for noticeably longer than the timeout.
	for i := 0; i < 6; i++ {
		time.Sleep(50 * time.Millisecond)
		if err := s.withVault(func(*vault.Vault) (bool, error) { return false, nil }); err != nil {
			t.Fatalf("vault access %d failed: %v", i, err)
		}
	}

	if !s.IsUnlocked() {
		t.Error("the vault locked despite continuous use")
	}
}

// Polling status must NOT keep the vault open: anything that polls in the
// background would otherwise hold the DEK in memory indefinitely.
func TestStatusDoesNotDeferAutolock(t *testing.T) {
	s := newSessionWithTimeout(t, 150*time.Millisecond)

	for i := 0; i < 6; i++ {
		time.Sleep(50 * time.Millisecond)
		if _, rerr := s.handleStatus(); rerr != nil {
			t.Fatalf("status failed: %+v", rerr)
		}
	}

	if s.IsUnlocked() {
		t.Error("polling status kept the vault unlocked")
	}
}

func TestAutolockDisabledWithZeroTimeout(t *testing.T) {
	s := newSessionWithTimeout(t, 0)

	time.Sleep(200 * time.Millisecond)

	if !s.IsUnlocked() {
		t.Error("the vault locked even though autolock is disabled")
	}
	if got := s.LocksIn(); got != -1 {
		t.Errorf("LocksIn with autolock disabled = %v, want -1", got)
	}
}

func TestLocksInCountsDown(t *testing.T) {
	s := newSessionWithTimeout(t, time.Minute)

	first := s.LocksIn()
	if first <= 0 || first > time.Minute {
		t.Fatalf("LocksIn = %v, want a value in (0, 1m]", first)
	}

	time.Sleep(50 * time.Millisecond)
	if second := s.LocksIn(); second >= first {
		t.Errorf("LocksIn did not decrease: %v then %v", first, second)
	}

	s.Lock()
	if got := s.LocksIn(); got != -1 {
		t.Errorf("LocksIn while locked = %v, want -1", got)
	}
}
