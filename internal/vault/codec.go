package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/chetankar/openpass/internal/crypto"
)

const (
	// preambleLen is magic(8) + format_ver(1) + header_len(4).
	preambleLen = 13

	formatVersion = 0x01
	cipherName    = "xchacha20poly1305"
)

var magic = [8]byte{'O', 'P', 'E', 'N', 'P', 'A', 'S', 'S'}

var (
	// ErrBadPassword means the master password did not unwrap the DEK i.e wrong password
	ErrBadPassword = errors.New("incorrect master password")

	// ErrStorage means the file is not a vault we can read: bad magic, an
	// unsupported version, a malformed header etc
	ErrStorage = errors.New("vault file is corrupt or has been tampered with")

	// ErrVaultExists guards Init against overwriting a vault.
	ErrVaultExists = errors.New("a vault already exists at this path")
)

// Encode encrypts the vault's entries and writes the complete vault.opv file at
// path, replacing any existing file atomically.
// Encode mutates v: it generates a fresh Header.BodyNonce, bumps
// Header.Revision, and sets Header.UpdatedAt.
func Encode(path string, v *Vault, dek *crypto.Secret) error {
	data, err := encodeBytes(v, dek)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data)
}

// encodeBytes builds the on-disk representation.
func encodeBytes(v *Vault, dek *crypto.Secret) ([]byte, error) {
	if v == nil {
		return nil, fmt.Errorf("cannot encode a nil vault")
	}
	if dek == nil || len(dek.GetSecret()) == 0 {
		return nil, fmt.Errorf("cannot encode with an empty DEK")
	}
	if len(v.Header.Wraps) == 0 {
		return nil, fmt.Errorf("header has no wraps: the vault must be initialised before it can be encoded")
	}

	// Serializing the body produces every password in the clear, so it is
	// zeroed as soon as it has been sealed.
	plaintext, err := json.Marshal(v.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal vault body: %v", err)
	}
	defer zero(plaintext)

	// A fresh nonce on every save, generated here rather than accepted from the
	// caller.
	v.Header.BodyNonce = crypto.GenerateNonce()

	now := time.Now().UTC().Format(time.RFC3339)
	if v.Header.CreatedAt == "" {
		v.Header.CreatedAt = now
	}
	v.Header.UpdatedAt = now
	v.Header.Revision++
	v.Header.Version = formatVersion
	v.Header.Cipher = cipherName

	// The AAD must be built after every header field is final: it authenticates
	// the header, so anything set afterwards would not be covered.
	aad, err := v.Header.CanonicalAAD() // contains the blanked wraps[].ct fields, not the real ciphertexts
	if err != nil {
		return nil, err
	}

	body, err := crypto.Seal(dek.GetSecret(), v.Header.BodyNonce, plaintext, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to seal vault body: %v", err)
	}

	// The stored header keeps its ct fields; only the AAD blanks them.
	headerJSON, err := GetHeaderJSON(v.Header)
	if err != nil {
		return nil, err
	}

	v.Magic = magic
	v.FormatVer = formatVersion
	v.HeaderLen = uint32(len(headerJSON))

	out := make([]byte, 0, preambleLen+len(headerJSON)+len(body))
	out = append(out, v.Magic[:]...)
	out = append(out, v.FormatVer)
	out = binary.BigEndian.AppendUint32(out, v.HeaderLen)
	out = append(out, headerJSON...)
	out = append(out, body...)

	return out, nil
}

// Decode reads the vault at path, unlocks it with password, and returns it
// along with the DEK needed to save it again.
//
// The caller owns the returned DEK and must ClearSecret it on lock.
func Decode(path string, password []byte) (*Vault, *crypto.Secret, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read vault: %w", err)
	}
	return decodeBytes(raw, password)
}

func decodeBytes(raw, password []byte) (*Vault, *crypto.Secret, error) {
	if len(raw) < preambleLen {
		return nil, nil, fmt.Errorf("%w: file is %d bytes, shorter than the %d-byte preamble", ErrStorage, len(raw), preambleLen)
	}
	if !bytes.Equal(raw[:len(magic)], magic[:]) {
		return nil, nil, fmt.Errorf("%w: not an openpass vault", ErrStorage)
	}
	if raw[8] != formatVersion {
		return nil, nil, fmt.Errorf("%w: unsupported format version %#x", ErrStorage, raw[8])
	}

	headerLen := binary.BigEndian.Uint32(raw[9:preambleLen])
	if uint64(headerLen) > uint64(len(raw)-preambleLen) {
		return nil, nil, fmt.Errorf("%w: header length %d exceeds the file", ErrStorage, headerLen)
	}

	headerJSON := raw[preambleLen : preambleLen+int(headerLen)]
	body := raw[preambleLen+int(headerLen):]

	header, err := SetHeader(headerJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrStorage, err)
	}

	// Before the AAD can be trusted, the stored bytes must be exactly the
	// canonical form.
	if err := VerifyCanonical(headerJSON, header); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrStorage, err)
	}
	if header.Cipher != cipherName {
		return nil, nil, fmt.Errorf("%w: unsupported cipher %q", ErrStorage, header.Cipher)
	}

	wrap, err := header.passwordWrap()
	if err != nil {
		return nil, nil, err
	}

	params := &crypto.Argon2Params{
		Time:        header.KDF.T,
		Memory:      header.KDF.MKiB,
		Parallelism: header.KDF.P,
	}
	kekBytes, err := params.DeriveKey(password, header.KDF.Salt)
	if err != nil {
		// Bad parameters or a short salt are properties of the file, not of the
		// password the user typed.
		return nil, nil, fmt.Errorf("%w: %v", ErrStorage, err)
	}
	kek := crypto.SetSecret(kekBytes)
	zero(kekBytes)
	// The KEK's only job is the unwrap below; it does not outlive this function.
	defer kek.ClearSecret()

	wrapAAD, err := header.WrapAAD(wrap)
	if err != nil {
		return nil, nil, err
	}

	// Open #1. There is no stored password hash anywhere in the vault — this
	// failing *is* the wrong-password signal.
	dekBytes, err := crypto.Open(kek.GetSecret(), wrap.Nonce, wrap.Ciphertext, wrapAAD)
	if err != nil {
		return nil, nil, ErrBadPassword
	}
	dek := crypto.SetSecret(dekBytes)
	zero(dekBytes)

	bodyAAD, err := header.CanonicalAAD()
	if err != nil {
		dek.ClearSecret()
		return nil, nil, err
	}

	// Open #2. Reaching here means the password was right, so a failure now is
	// not a typo: the file was modified. Reporting it as ErrBadPassword would
	// send the user hunting for a mistake that is not theirs.
	plaintext, err := crypto.Open(dek.GetSecret(), header.BodyNonce, body, bodyAAD)
	if err != nil {
		dek.ClearSecret()
		return nil, nil, fmt.Errorf("%w: the body failed authentication even though the password was correct", ErrStorage)
	}
	defer zero(plaintext)

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		dek.ClearSecret()
		return nil, nil, fmt.Errorf("%w: failed to parse the vault body: %v", ErrStorage, err)
	}

	return &Vault{
		Magic:     magic,
		FormatVer: formatVersion,
		HeaderLen: headerLen,
		Header:    header,
		Body:      entries,
	}, dek, nil
}

// passwordWrap returns the wrap that the master password unlocks.
func (h Header) passwordWrap() (Wrap, error) {
	for _, w := range h.Wraps {
		if w.Kind == wrapKindPassword {
			return w, nil
		}
	}
	return Wrap{}, fmt.Errorf("%w: the header has no password wrap", ErrStorage)
}

// Writes a temporary file
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)

	tmpName, err := writeTempFile(dir, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmpName) // no-op once the rename has succeeded

	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("failed to rename temp file into place: %w", err)
	}

	// fsync the directory so the rename itself is durable.
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("failed to open directory for sync: %v", err)
	}
	defer d.Close()

	if err := d.Sync(); err != nil {
		return fmt.Errorf("failed to sync directory: %v", err)
	}
	return nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
