package crypto

import (
	"bytes"
	"testing"
)

func TestAEAD(t *testing.T) {
	key := []byte("01234567890123456789012345678901") // 32 bytes key for XChaCha20-Poly1305
	nonce := GenerateNonce()
	plaintext := []byte("Hello, World!")
	additionalData := []byte("Additional Data") /// for authenticate

	ciphertext, err := Seal(key, nonce, plaintext, additionalData)
	if err != nil {
		t.Fatalf("Failed to seal: %v", err)
	}

	/// As the nonce will be stored in the vault header, we can read it back and get the plaintext.
	decrypted, err := Open(key, nonce, ciphertext, additionalData)
	if err != nil {
		t.Fatalf("Failed to open: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decrypted plaintext does not match original")
	}

	t.Logf("Original: %s, Decrypted: %s", plaintext, decrypted)
}

// A nonce of the wrong length must be an error, not a panic: the nonce is read
// from the vault's plaintext header before it has been authenticated.
func TestAEADRejectsBadNonceLength(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	short := make([]byte, 12) // A 12-byte nonce is invalid for XChaCha20-Poly1305.

	if _, err := Seal(key, short, []byte("plaintext"), nil); err == nil {
		t.Error("Seal accepted a 12-byte nonce")
	}
	if _, err := Open(key, short, make([]byte, 32), nil); err == nil {
		t.Error("Open accepted a 12-byte nonce")
	}
}
