package crypto

import (
	"bytes"
	"testing"
)

// / End to end testing of the KDF module with default and tuned Argon2 parameters
func TestKDF(t *testing.T) {
	params := DefaultArgon2Params()

	// Generate a random salt
	salt, err := GenerateSalt(MinSaltLength)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	password := []byte("testpassword")

	// Derive a key using the default parameters
	key1, err := params.DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// Derive a key again with the same password and salt
	key2, err := params.DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// The derived keys should be the same
	if !bytes.Equal(key1, key2) {
		t.Errorf("Derived keys do not match")
	}

	t.Logf("Derived key: %x, %x", key1, key2)

	// Tune the parameters and derive a new key from the same password and salt
	params.Tune(4, 128*1024, 8)

	key3, err := params.DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	// The new derived key should be different from the previous one
	if bytes.Equal(key1, key3) {
		t.Errorf("Derived keys should not match after tuning parameters")
	}

	t.Logf("Old key and New Key: %x, %x", key1, key3)
}

// The derived key feeds XChaCha20-Poly1305, so it must always be a valid AEAD key.
func TestDeriveKeyProducesAEADKey(t *testing.T) {
	params := DefaultArgon2Params()
	salt, err := GenerateSalt(MinSaltLength)
	if err != nil {
		t.Fatalf("Failed to generate salt: %v", err)
	}

	key, err := params.DeriveKey([]byte("testpassword"), salt)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}

	if _, err := Seal(key, GenerateNonce(), []byte("plaintext"), nil); err != nil {
		t.Errorf("Derived key was not usable as an AEAD key: %v", err)
	}
}

func TestDeriveKeyRejectsShortSalt(t *testing.T) {
	params := DefaultArgon2Params()

	if _, err := params.DeriveKey([]byte("testpassword"), make([]byte, MinSaltLength-1)); err == nil {
		t.Errorf("DeriveKey accepted a salt shorter than %d bytes", MinSaltLength)
	}
}
