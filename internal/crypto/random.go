package crypto

import (
	"crypto/rand"
	"fmt"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
)

// GenerateSalt returns length cryptographically random bytes, for use as an
// Argon2id salt. See MinSaltLength.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}
	return salt, nil
}

// GenerateKey returns a fresh random key for XChaCha20-Poly1305, already
// wrapped in a Secret so it is locked and zeroable. This is how a vault's DEK
// is created.
func GenerateKey() (*Secret, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	s := SetSecret(key)
	for i := range key {
		key[i] = 0
	}
	runtime.KeepAlive(key)
	return s, nil
}

// GenerateNonce returns a fresh XChaCha20-Poly1305 nonce.
func GenerateNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		panic(fmt.Sprintf("failed to generate nonce: %v", err))
	}
	return nonce
}
