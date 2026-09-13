package vault

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chetankar/openpass/internal/crypto"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	s, err := NewStore(filepath.Join(t.TempDir(), "vault.opv"))
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestStoreInitLoadSave(t *testing.T) {
	s := newTestStore(t)

	if s.Exists() {
		t.Error("a fresh store reports an existing vault")
	}

	v, dek, err := s.Init(testPassword, cheapParams())
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer dek.ClearSecret()

	v.AddEntry(Entry{ID: "1", Name: "GitHub", Secret: *crypto.SetSecret([]byte("hunter2"))})
	if err := s.Save(v, dek); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, loadedDEK, err := s.Load(testPassword)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer loadedDEK.ClearSecret()

	if len(loaded.Body) != 1 || loaded.Body[0].Name != "GitHub" {
		t.Errorf("round trip lost the entry: %+v", loaded.Body)
	}
}

// A second process must fail immediately and clearly, not block or corrupt.
func TestStoreLockIsExclusive(t *testing.T) {
	s := newTestStore(t)

	_, err := NewStore(s.path)
	if !errors.Is(err, ErrVaultLocked) {
		t.Errorf("second NewStore err = %v, want ErrVaultLocked", err)
	}

	// The lock must be released on Close, or a daemon restart would deadlock.
	if err := s.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	again, err := NewStore(s.path)
	if err != nil {
		t.Fatalf("could not reacquire the lock after Close: %v", err)
	}
	again.Close()
}

// A save keeps exactly one previous generation.
func TestStoreRotatesBackup(t *testing.T) {
	s := newTestStore(t)

	v, dek, err := s.Init(testPassword, cheapParams())
	if err != nil {
		t.Fatal(err)
	}
	defer dek.ClearSecret()

	if _, err := os.Stat(s.backupPath()); !os.IsNotExist(err) {
		t.Error("Init created a backup before any save")
	}

	v.AddEntry(Entry{ID: "1", Name: "GitHub"})
	if err := s.Save(v, dek); err != nil {
		t.Fatal(err)
	}

	bak, err := os.ReadFile(s.backupPath())
	if err != nil {
		t.Fatalf("no backup after a save: %v", err)
	}

	// The backup must be the *previous* generation, i.e. the empty vault.
	prev, prevDEK, err := decodeBytes(bak, testPassword)
	if err != nil {
		t.Fatalf("the backup does not decrypt: %v", err)
	}
	defer prevDEK.ClearSecret()

	if len(prev.Body) != 0 {
		t.Errorf("backup holds %d entries, want the pre-save state of 0", len(prev.Body))
	}
}

// If something else rewrites the file while we hold it open, Save must refuse
// rather than silently discard that change.
func TestStoreDetectsConcurrentModification(t *testing.T) {
	s := newTestStore(t)

	v, dek, err := s.Init(testPassword, cheapParams())
	if err != nil {
		t.Fatal(err)
	}
	defer dek.ClearSecret()

	// Simulate a restore from backup / another tool: a different revision lands
	// on disk behind our back.
	other := NewVault()
	other.Header = v.Header
	other.Header.Revision = 99
	if err := Encode(s.path, other, dek); err != nil {
		t.Fatal(err)
	}

	v.AddEntry(Entry{ID: "1", Name: "GitHub"})
	err = s.Save(v, dek)
	if !errors.Is(err, ErrConcurrentModification) {
		t.Errorf("Save err = %v, want ErrConcurrentModification", err)
	}
}

func TestStoreDetectsDeletedVault(t *testing.T) {
	s := newTestStore(t)

	v, dek, err := s.Init(testPassword, cheapParams())
	if err != nil {
		t.Fatal(err)
	}
	defer dek.ClearSecret()

	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}

	if err := s.Save(v, dek); !errors.Is(err, ErrConcurrentModification) {
		t.Errorf("Save err = %v, want ErrConcurrentModification", err)
	}
}

// Save must prove the new bytes decrypt before replacing the good vault.
func TestStoreVerifiesBeforeCommitting(t *testing.T) {
	s := newTestStore(t)

	v, dek, err := s.Init(testPassword, cheapParams())
	if err != nil {
		t.Fatal(err)
	}
	defer dek.ClearSecret()

	good, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}

	// A DEK that is not the vault's: encodeBytes succeeds, but the result is
	// unopenable. This stands in for any bug that produces a bad file.
	wrongDEK, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer wrongDEK.ClearSecret()

	// verifyEncoded must reject it.
	data, err := encodeBytes(v, wrongDEK)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyEncoded(data, dek); err == nil {
		t.Error("verifyEncoded accepted a vault sealed under a different key")
	}

	// And the good vault on disk must be untouched.
	after, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(good) {
		t.Error("the existing vault was modified by a failed save")
	}
}

// The window between the two renames in Save leaves the vault missing and the
// backup present. Load must recognise that rather than reporting "no vault".
func TestStoreReportsInterruptedSave(t *testing.T) {
	s := newTestStore(t)

	v, dek, err := s.Init(testPassword, cheapParams())
	if err != nil {
		t.Fatal(err)
	}
	defer dek.ClearSecret()

	v.AddEntry(Entry{ID: "1", Name: "GitHub"})
	if err := s.Save(v, dek); err != nil {
		t.Fatal(err)
	}

	// Recreate the crash state: vault gone, backup present.
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}

	_, _, err = s.Load(testPassword)
	if err == nil {
		t.Fatal("Load succeeded with no vault file")
	}
	if !errors.Is(err, ErrStorage) {
		t.Errorf("err = %v, want ErrStorage", err)
	}
	// The message has to name the backup, or the user cannot act on it.
	if !strings.Contains(err.Error(), ".bak") {
		t.Errorf("error does not mention the backup: %v", err)
	}
}
