package vault

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/chetankar/openpass/internal/crypto"
)

var testPassword = []byte("correct-horse-battery-staple")

// cheapParams keeps Argon2id fast enough for a test suite. Real vaults use
// DefaultArgon2Params; the KDF's strength is covered in internal/crypto.
func cheapParams() *crypto.Argon2Params {
	return &crypto.Argon2Params{Time: 1, Memory: 64, Parallelism: 1}
}

func initTestVault(t *testing.T) (string, *Vault, *crypto.Secret) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "vault.opv")
	v, dek, err := Init(path, testPassword, cheapParams())
	if err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	t.Cleanup(dek.ClearSecret)
	return path, v, dek
}

func TestInitThenDecode(t *testing.T) {
	path, _, dek := initTestVault(t)

	opened, openedDEK, err := Decode(path, testPassword)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	defer openedDEK.ClearSecret()

	// The whole point of the wrap: the DEK that comes back out is the one Init
	// generated, recovered via the password.
	if !bytes.Equal(dek.GetSecret(), openedDEK.GetSecret()) {
		t.Error("Decode returned a different DEK than Init created")
	}
	if opened.Header.KDF.Alg != kdfAlgArgon2id {
		t.Errorf("kdf.alg = %q, want %q", opened.Header.KDF.Alg, kdfAlgArgon2id)
	}
	if len(opened.Body) != 0 {
		t.Errorf("a new vault has %d entries, want 0", len(opened.Body))
	}
}

// The regression test for the wrap AAD. A wrap sealed against the full header
// would be invalidated by the first Encode, because body_nonce, rev and
// updated_at all change on every save — leaving the vault permanently
// unopenable. Saving must not disturb the wraps.
func TestVaultSurvivesRepeatedSaves(t *testing.T) {
	path, v, dek := initTestVault(t)

	for i := 0; i < 3; i++ {
		v.AddEntry(Entry{
			ID:     "entry",
			Name:   "GitHub",
			Secret: *crypto.SetSecret([]byte("hunter2")),
		})
		if err := Encode(path, v, dek); err != nil {
			t.Fatalf("Encode %d failed: %v", i, err)
		}

		opened, openedDEK, err := Decode(path, testPassword)
		if err != nil {
			t.Fatalf("Decode after save %d failed: %v", i, err)
		}
		if len(opened.Body) != i+1 {
			t.Errorf("after save %d: %d entries, want %d", i, len(opened.Body), i+1)
		}
		openedDEK.ClearSecret()
	}
}

func TestDecodeRoundTripsEntries(t *testing.T) {
	path, v, dek := initTestVault(t)

	v.AddEntry(Entry{
		ID:       "3f2a",
		Name:     "GitHub",
		Username: "chetan",
		Secret:   *crypto.SetSecret([]byte("hunter2")),
		URLs:     []string{"https://github.com"},
		Tags:     []string{"work"},
	})
	if err := Encode(path, v, dek); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	opened, openedDEK, err := Decode(path, testPassword)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	defer openedDEK.ClearSecret()

	if len(opened.Body) != 1 {
		t.Fatalf("got %d entries, want 1", len(opened.Body))
	}
	got := opened.Body[0]
	if got.Name != "GitHub" || got.Username != "chetan" {
		t.Errorf("entry = %q/%q, want GitHub/chetan", got.Name, got.Username)
	}
	if string(got.Secret.GetSecret()) != "hunter2" {
		t.Errorf("secret did not survive the round trip")
	}
}

func TestDecodeWrongPassword(t *testing.T) {
	path, _, _ := initTestVault(t)

	_, _, err := Decode(path, []byte("not-the-password"))
	if !errors.Is(err, ErrBadPassword) {
		t.Errorf("err = %v, want ErrBadPassword", err)
	}
}

// A body that fails to open *after* the DEK unwrapped cleanly means the file
// was modified by someone who did not know the password. Reporting that as a
// wrong password would send the user looking for a typo.
func TestDecodeTamperedBodyIsNotAPasswordError(t *testing.T) {
	path, _, _ := initTestVault(t)

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01 // last byte of the body's tag
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}

	_, _, err = Decode(path, testPassword)
	if !errors.Is(err, ErrStorage) {
		t.Errorf("err = %v, want ErrStorage", err)
	}
	if errors.Is(err, ErrBadPassword) {
		t.Error("a tampered body was reported as a wrong password")
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	path, _, _ := initTestVault(t)

	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = Init(path, []byte("a-different-password"), cheapParams())
	if !errors.Is(err, ErrVaultExists) {
		t.Errorf("err = %v, want ErrVaultExists", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the existing vault was modified")
	}
}

func TestInitRejectsEmptyPassword(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.opv")

	if _, _, err := Init(path, nil, cheapParams()); err == nil {
		t.Error("Init accepted an empty master password")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("Init wrote a file despite failing")
	}
}

// rebuildFile reassembles a vault file around a replacement header, fixing up
// header_len so the result is structurally valid.
func rebuildFile(t *testing.T, raw []byte, h Header) []byte {
	t.Helper()

	headerJSON, err := GetHeaderJSON(h)
	if err != nil {
		t.Fatal(err)
	}
	oldLen := int(binary.BigEndian.Uint32(raw[9:preambleLen]))
	body := raw[preambleLen+oldLen:]

	out := append([]byte(nil), raw[:9]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(headerJSON)))
	out = append(out, headerJSON...)
	return append(out, body...)
}

// Decode parses attacker-controlled bytes before anything is authenticated, so
// no input may panic. argon2 in particular panics outright on time < 1.
func TestDecodeMalformedInputDoesNotPanic(t *testing.T) {
	path, _, _ := initTestVault(t)
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	header, err := SetHeader(good[preambleLen : preambleLen+int(binary.BigEndian.Uint32(good[9:preambleLen]))])
	if err != nil {
		t.Fatal(err)
	}

	zeroTime := header
	zeroTime.KDF.T = 0

	zeroParallelism := header
	zeroParallelism.KDF.P = 0

	noWraps := header
	noWraps.Wraps = nil

	hugeHeaderLen := append([]byte(nil), good...)
	binary.BigEndian.PutUint32(hugeHeaderLen[9:preambleLen], 0xFFFFFFFF)

	badVersion := append([]byte(nil), good...)
	badVersion[8] = 0xFF

	badMagic := append([]byte(nil), good...)
	badMagic[0] = 'X'

	cases := map[string][]byte{
		"empty":            {},
		"preamble only":    good[:preambleLen],
		"truncated":        good[:len(good)/2],
		"bad magic":        badMagic,
		"bad version":      badVersion,
		"huge header_len":  hugeHeaderLen,
		"argon2 time 0":    rebuildFile(t, good, zeroTime),
		"argon2 threads 0": rebuildFile(t, good, zeroParallelism),
		"no wraps":         rebuildFile(t, good, noWraps),
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			v, dek, err := decodeBytes(raw, testPassword)
			if err == nil {
				t.Fatalf("malformed input was accepted: %+v", v)
			}
			if dek != nil {
				t.Error("a DEK was returned alongside an error")
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	path, _, _ := initTestVault(&testing.T{})
	if good, err := os.ReadFile(path); err == nil {
		f.Add(good)
	}
	f.Add([]byte{})
	f.Add(append([]byte("OPENPASS"), 0x01, 0, 0, 0, 0))

	f.Fuzz(func(t *testing.T, raw []byte) {
		// The only requirement is that it does not panic.
		if _, dek, err := decodeBytes(raw, testPassword); err == nil && dek != nil {
			dek.ClearSecret()
		}
	})
}
