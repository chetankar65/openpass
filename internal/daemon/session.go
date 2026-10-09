package daemon

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/chetankar/openpass/internal/crypto"
	"github.com/chetankar/openpass/internal/vault"
)

// DefaultIdleTimeout is how long an unlocked vault survives without use.
//
// This is the security control that actually matters for memory exposure: the
// plaintext vault is in daemon memory the whole time it is unlocked, and
// nothing can prevent a same-user attacker reading it (DESIGN.md §2). All we
// can do is keep the window short.
const DefaultIdleTimeout = 15 * time.Minute

// Session is the daemon's unlocked state: the DEK and the decrypted vault,
// held in memory so that everything after unlock is a map lookup instead of
// another Argon2id run.
//
// It is the only mutable state in the process, and every handler goes through
// it, so it carries the mutex. The daemon accepts concurrent connections.
type Session struct {
	mu sync.Mutex

	// store holds the flock for the daemon's lifetime, which is what makes
	// this process the single writer.
	store *vault.Store

	// Both are nil when locked.
	v   *vault.Vault
	dek *crypto.Secret

	// idleTimeout of zero disables autolock. lockTimer is non-nil only while
	// unlocked; lockAt is when it will fire, for reporting in status.
	idleTimeout time.Duration
	lockTimer   *time.Timer
	lockAt      time.Time

	// onLock runs after the vault is locked, to drop anything scoped to the
	// unlocked session.
	onLock func()
}

func (s *Session) SetOnLock(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onLock = fn
}

func NewSession(vaultPath string, idleTimeout time.Duration) (*Session, error) {
	store, err := vault.NewStore(vaultPath)
	if err != nil {
		return nil, err
	}
	return &Session{store: store, idleTimeout: idleTimeout}, nil
}

// Close locks the vault and releases the file lock.
func (s *Session) Close() error {
	s.Lock()
	return s.store.Close()
}

func (s *Session) IsUnlocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dek != nil
}

func (s *Session) HasVault() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.store.Exists()
}

// EntryCount returns how many entries are loaded, or -1 when locked.
//
// A locked vault reports nothing about its contents, not even its size.
func (s *Session) EntryCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.v == nil {
		return -1
	}
	return len(s.v.Body)
}

// Init creates a new vault and leaves the session unlocked, since whoever just
// set the password has plainly authenticated.
func (s *Session) Init(password []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, dek, err := s.store.Init(password, nil)
	if err != nil {
		return err
	}

	s.clearLocked()
	s.v, s.dek = v, dek
	s.armTimerLocked()
	return nil
}

// Unlock derives the KEK, unwraps the DEK and decrypts the vault. This is the
// only slow operation in the daemon (~500ms, by design).
func (s *Session) Unlock(password []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	v, dek, err := s.store.Load(password)
	if err != nil {
		return err
	}

	s.clearLocked()
	s.v, s.dek = v, dek
	s.armTimerLocked()
	return nil
}

// Lock zeroes the DEK and drops the decrypted entries. Idempotent.
func (s *Session) Lock() {
	s.mu.Lock()
	s.clearLocked()
	fn := s.onLock
	s.mu.Unlock()

	if fn != nil {
		fn()
	}
}

// clearLocked wipes the unlocked state. The caller must hold s.mu.
func (s *Session) clearLocked() {
	if s.lockTimer != nil {
		s.lockTimer.Stop()
		s.lockTimer = nil
	}
	s.lockAt = time.Time{}

	if s.dek != nil {
		s.dek.ClearSecret()
		s.dek = nil
	}
	s.v = nil
}

// armTimerLocked starts the autolock countdown. The caller must hold s.mu.
func (s *Session) armTimerLocked() {
	if s.idleTimeout <= 0 {
		return
	}

	s.lockAt = time.Now().Add(s.idleTimeout)
	// AfterFunc runs the callback on its own goroutine, so it will block on
	// s.mu until whoever armed it has let go. Lock() is idempotent, so a
	// callback that fires during an explicit lock is harmless.
	s.lockTimer = time.AfterFunc(s.idleTimeout, func() {
		log.Printf("idle for %s, locking the vault", s.idleTimeout)
		s.Lock()
	})
}

// touchLocked pushes the autolock deadline back. The caller must hold s.mu.
//
// Only operations that actually reach the vault call this. A passive poll like
// status must not keep the vault open — otherwise anything that polls in the
// background holds the DEK in memory indefinitely, which is exactly what the
// timeout exists to prevent.
func (s *Session) touchLocked() {
	if s.lockTimer == nil || s.idleTimeout <= 0 {
		return
	}
	s.lockTimer.Stop()
	s.armTimerLocked()
}

// LocksIn reports the time until autolock, or -1 when locked or when autolock
// is disabled.
func (s *Session) LocksIn() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dek == nil || s.lockAt.IsZero() {
		return -1
	}
	if d := time.Until(s.lockAt); d > 0 {
		return d
	}
	return 0
}

// withVault runs fn against the unlocked vault under the session lock. If fn
// returns true, the vault is saved.
//
// Every handler goes through this so that the locked check, the mutex and the
// save path exist in exactly one place.
func (s *Session) withVault(fn func(v *vault.Vault) (dirty bool, err error)) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.dek == nil {
		return ErrLocked
	}
	s.touchLocked()

	dirty, err := fn(s.v)
	if err != nil {
		return err
	}
	if !dirty {
		return nil
	}

	if err := s.store.Save(s.v, s.dek); err != nil {
		return fmt.Errorf("failed to save the vault: %w", err)
	}
	return nil
}
