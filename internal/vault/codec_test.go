package vault

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/chetankar/openpass/internal/crypto"
)

// testVault returns an initialised vault with one entry, plus the DEK its body
// is sealed under.
func testVault(t *testing.T) (*Vault, *crypto.Secret) {
	t.Helper()

	dek := crypto.SetSecret(bytes.Repeat([]byte{0xAB}, 32))
	t.Cleanup(dek.ClearSecret)

	v := NewVault()
	v.Header.KDF.Alg = "argon2id"
	v.Header.KDF.Salt = bytes.Repeat([]byte{0x11}, 16)
	v.Header.KDF.MKiB = 65536
	v.Header.KDF.T = 3
	v.Header.KDF.P = 4
	// Encode does not create wraps; a real one is written by vault init.
	v.Header.Wraps = []Wrap{{
		ID:         "master",
		Kind:       "password",
		Nonce:      crypto.GenerateNonce(),
		Ciphertext: bytes.Repeat([]byte{0xCD}, 48),
	}}

	v.AddEntry(Entry{
		ID:       "3f2a",
		Name:     "GitHub",
		Username: "chetan",
		Secret:   *crypto.SetSecret([]byte("correct-horse-battery-staple")),
		URLs:     []string{"https://github.com"},
	})

	return v, dek
}

func TestEncodeWritesReadableVault(t *testing.T) {
	v, dek := testVault(t)
	path := filepath.Join(t.TempDir(), "vault.opv")

	if err := Encode(path, v, dek); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read vault: %v", err)
	}

	// Preamble
	if got := string(raw[:8]); got != "OPENPASS" {
		t.Errorf("magic = %q, want OPENPASS", got)
	}
	if raw[8] != formatVersion {
		t.Errorf("format_ver = %#x, want %#x", raw[8], formatVersion)
	}

	headerLen := binary.BigEndian.Uint32(raw[9:13])
	if int(headerLen) > len(raw)-preambleLen {
		t.Fatalf("header_len %d exceeds the file", headerLen)
	}

	// Header parses, and reports what we set.
	header, err := SetHeader(raw[preambleLen : preambleLen+int(headerLen)])
	if err != nil {
		t.Fatalf("Failed to parse header: %v", err)
	}
	if header.Cipher != cipherName {
		t.Errorf("cipher = %q, want %q", header.Cipher, cipherName)
	}
	if header.Revision != 1 {
		t.Errorf("rev = %d, want 1 after the first save", header.Revision)
	}

	// The body decrypts under the DEK, with the AAD rebuilt from the header we
	// just read back rather than the one still in memory.
	aad, err := header.CanonicalAAD()
	if err != nil {
		t.Fatalf("CanonicalAAD failed: %v", err)
	}

	plaintext, err := crypto.Open(dek.GetSecret(), header.BodyNonce, raw[preambleLen+int(headerLen):], aad)
	if err != nil {
		t.Fatalf("Failed to open the vault body: %v", err)
	}

	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		t.Fatalf("Failed to unmarshal entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if entries[0].Name != "GitHub" {
		t.Errorf("name = %q, want GitHub", entries[0].Name)
	}
	if got := string(entries[0].Secret.GetSecret()); got != "correct-horse-battery-staple" {
		t.Errorf("secret = %q, want the original password", got)
	}
}

// The plaintext must not be recoverable from the file without the key.
func TestEncodeLeaksNothingInPlaintext(t *testing.T) {
	v, dek := testVault(t)
	path := filepath.Join(t.TempDir(), "vault.opv")

	if err := Encode(path, v, dek); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read vault: %v", err)
	}

	for _, secret := range []string{"correct-horse-battery-staple", "GitHub", "chetan", "github.com"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("%q appears in the encrypted file in the clear", secret)
		}
	}
}

// Every save must use a new nonce.
func TestEncodeUsesFreshNonceEverySave(t *testing.T) {
	v, dek := testVault(t)
	path := filepath.Join(t.TempDir(), "vault.opv")

	if err := Encode(path, v, dek); err != nil {
		t.Fatalf("First Encode failed: %v", err)
	}
	first := append([]byte(nil), v.Header.BodyNonce...)

	if err := Encode(path, v, dek); err != nil {
		t.Fatalf("Second Encode failed: %v", err)
	}

	if bytes.Equal(first, v.Header.BodyNonce) {
		t.Error("body_nonce was reused across saves")
	}
	if v.Header.Revision != 2 {
		t.Errorf("rev = %d, want 2 after two saves", v.Header.Revision)
	}
}

// Tampering with any byte of the header must be detected, because the header is
// the AAD.

func TestEncodedHeaderIsTamperEvident(t *testing.T) {
	v, dek := testVault(t)
	path := filepath.Join(t.TempDir(), "vault.opv")

	if err := Encode(path, v, dek); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read vault: %v", err)
	}
	headerLen := int(binary.BigEndian.Uint32(raw[9:13]))
	header := raw[preambleLen : preambleLen+headerLen]

	// The wraps' ct values are deliberately outside the body's AAD:
	ctStart, ctEnd := ctValueRange(t, header)

	for i := preambleLen; i < preambleLen+headerLen; i++ {
		if off := i - preambleLen; off >= ctStart && off < ctEnd {
			continue
		}
		corrupt := append([]byte(nil), raw...)
		corrupt[i] ^= 0x01

		corruptHeader := corrupt[preambleLen : preambleLen+headerLen]

		header, err := SetHeader(corruptHeader)
		if err != nil {
			continue // a flip that breaks the JSON is detected too
		}
		if err := VerifyCanonical(corruptHeader, header); err != nil {
			continue // detected: the stored bytes are not the canonical form
		}
		aad, err := header.CanonicalAAD()
		if err != nil {
			continue
		}
		if _, err := crypto.Open(dek.GetSecret(), header.BodyNonce, corrupt[preambleLen+headerLen:], aad); err == nil {
			t.Fatalf("byte %d: header tampering was not detected", i)
		}
	}
}

// ctValueRange returns the byte range of the single wrap's base64 ct value
// within the header JSON.
func ctValueRange(t *testing.T, header []byte) (int, int) {
	t.Helper()

	const key = `"ct":"`
	i := bytes.Index(header, []byte(key))
	if i < 0 {
		t.Fatalf("no ct field in header: %s", header)
	}
	start := i + len(key)

	n := bytes.IndexByte(header[start:], '"')
	if n < 0 {
		t.Fatalf("unterminated ct value in header: %s", header)
	}
	return start, start + n
}

func TestEncodeRejectsUninitialisedVault(t *testing.T) {
	dek := crypto.SetSecret(bytes.Repeat([]byte{0xAB}, 32))
	defer dek.ClearSecret()

	path := filepath.Join(t.TempDir(), "vault.opv")

	// No wraps: there is no DEK stored in the file, so this vault could never
	// be opened again.
	if err := Encode(path, NewVault(), dek); err == nil {
		t.Error("Encode accepted a vault with no wraps")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Encode wrote a file despite failing")
	}
}
