package vault

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chetankar/openpass/internal/crypto"
	"golang.org/x/sys/unix"
)

// ErrConcurrentModification means the file on disk is not the revision we last
// wrote or read, so something changed it behind our back.
var ErrConcurrentModification = errors.New("the vault file changed underneath us")

// ErrVaultLocked means another process holds the vault lock.
var ErrVaultLocked = errors.New("another openpass process has this vault open")

// Store owns a vault file: the exclusive lock on it, its backup.
type Store struct {
	path string
	// lock is held open for the Store's lifetime. Lock is released when the file descriptor closes
	lock *os.File
	// knownRev is the revision we believe is on disk. Save refuses to write if
	// the file disagrees.
	knownRev int
}

// NewStore takes the exclusive lock on the vault at path, creating the
// containing directory (0700) if it does not exist.
func NewStore(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create vault directory: %w", err)
	}

	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open vault lock: %w", err)
	}

	// LOCK_NB so a second daemon fails immediately with a clear message rather
	// than hanging forever on a lock it will never get.
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("%w: %s", ErrVaultLocked, path)
	}

	return &Store{path: path, lock: lock, knownRev: -1}, nil
}

// Close releases the vault lock.
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close() // releases the flock
	s.lock = nil
	return err
}

// Exists reports whether a vault file is present.
func (s *Store) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Init creates a new vault. It fails if one already exists.
func (s *Store) Init(password []byte, params *crypto.Argon2Params) (*Vault, *crypto.Secret, error) {
	v, dek, err := Init(s.path, password, params)
	if err != nil {
		return nil, nil, err
	}
	s.knownRev = v.Header.Revision
	return v, dek, nil
}

// Load unlocks the vault and remembers which revision it read, so a later Save
// can tell whether anything changed in between.
func (s *Store) Load(password []byte) (*Vault, *crypto.Secret, error) {
	if !s.Exists() {
		if _, err := os.Stat(s.backupPath()); err == nil {
			return nil, nil, fmt.Errorf(
				"%w: %s is missing but %s exists, which means a save was interrupted; "+
					"rename the backup over it to recover",
				ErrStorage, s.path, s.backupPath())
		}
		return nil, nil, fmt.Errorf("%w: no vault at %s", ErrStorage, s.path)
	}

	v, dek, err := Decode(s.path, password)
	if err != nil {
		return nil, nil, err
	}
	s.knownRev = v.Header.Revision
	return v, dek, nil
}

// Save encrypts and writes the vault, with three protections Encode does not
// provide:
//
//  1. A revision check, so a vault restored from backup or edited by another
//     tool is not silently clobbered.
//  2. Verification that the new file actually decrypts, *before* it replaces
//     the old one. Without this a bug in encoding destroys the only good copy.
//  3. Backup rotation, keeping one previous generation.
func (s *Store) Save(v *Vault, dek *crypto.Secret) error {
	if err := s.checkRevision(); err != nil {
		return err
	}

	data, err := encodeBytes(v, dek)
	if err != nil {
		return err
	}

	if err := verifyEncoded(data, dek); err != nil {
		return fmt.Errorf("refusing to save: the encoded vault did not verify: %w", err)
	}

	if err := s.writeWithBackup(data); err != nil {
		return err
	}

	s.knownRev = v.Header.Revision
	return nil
}

func (s *Store) backupPath() string { return s.path + ".bak" }

// checkRevision compares the revision on disk with the one we last saw.
func (s *Store) checkRevision() error {
	if s.knownRev < 0 {
		return nil // nothing loaded yet, nothing to compare against
	}

	onDisk, err := peekRevision(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: the vault file has been deleted", ErrConcurrentModification)
	}
	if err != nil {
		return err
	}

	if onDisk != s.knownRev {
		return fmt.Errorf("%w: on disk it is revision %d, we last saw %d; "+
			"reload before saving or the other change will be lost",
			ErrConcurrentModification, onDisk, s.knownRev)
	}
	return nil
}

// peekRevision reads just the header to find the revision. It does no
// decryption and needs no key.
func peekRevision(path string) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	if len(raw) < preambleLen {
		return 0, fmt.Errorf("%w: file is too short to hold a header", ErrStorage)
	}

	headerLen := binary.BigEndian.Uint32(raw[9:preambleLen])
	if uint64(headerLen) > uint64(len(raw)-preambleLen) {
		return 0, fmt.Errorf("%w: header length %d exceeds the file", ErrStorage, headerLen)
	}

	header, err := SetHeader(raw[preambleLen : preambleLen+int(headerLen)])
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrStorage, err)
	}
	return header.Revision, nil
}

// verifyEncoded re-reads freshly encoded bytes and confirms the body opens
// under dek.
//
// It cannot check the wraps — that needs the KEK, and so the master password,
// which Save does not have. It does not need to: Encode copies the wraps
// through untouched, so if they were good before they are good now. What this
// catches is a broken body seal, a mismatched AAD, or a truncated assembly.
func verifyEncoded(data []byte, dek *crypto.Secret) error {
	if len(data) < preambleLen {
		return fmt.Errorf("encoded vault is shorter than the preamble")
	}

	headerLen := binary.BigEndian.Uint32(data[9:preambleLen])
	if uint64(headerLen) > uint64(len(data)-preambleLen) {
		return fmt.Errorf("encoded header length %d exceeds the encoded vault", headerLen)
	}

	headerJSON := data[preambleLen : preambleLen+int(headerLen)]
	body := data[preambleLen+int(headerLen):]

	header, err := SetHeader(headerJSON)
	if err != nil {
		return err
	}
	if err := VerifyCanonical(headerJSON, header); err != nil {
		return err
	}

	aad, err := header.CanonicalAAD()
	if err != nil {
		return err
	}

	plaintext, err := crypto.Open(dek.GetSecret(), header.BodyNonce, body, aad)
	if err != nil {
		return fmt.Errorf("the body did not decrypt: %w", err)
	}
	zero(plaintext)
	return nil
}

// writeWithBackup writes data to a temporary file, then rotates the current
// vault to .bak and moves the new one into place.
func (s *Store) writeWithBackup(data []byte) error {
	dir := filepath.Dir(s.path)

	tmpName, err := writeTempFile(dir, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpName) // no-op once renamed

	if _, err := os.Stat(s.path); err == nil {
		if err := os.Rename(s.path, s.backupPath()); err != nil {
			return fmt.Errorf("failed to rotate the previous vault to a backup: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to check the existing vault: %w", err)
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("failed to move the new vault into place: %w", err)
	}

	return syncDir(dir)
}

// writeTempFile writes data to a new file in dir and fsyncs it, returning its
// name. The fsync must happen before any rename, or the rename can become
// durable while the contents have not.
func writeTempFile(dir string, data []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, ".vault-*.tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	name := tmp.Name()

	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", fmt.Errorf("failed to set permissions on temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", fmt.Errorf("failed to write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", fmt.Errorf("failed to sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", fmt.Errorf("failed to close temp file: %w", err)
	}

	return name, nil
}
