package crypto

import (
	"crypto/rand"
	"fmt"

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

// GenerateNonce returns a fresh XChaCha20-Poly1305 nonce.
func GenerateNonce() []byte {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		panic(fmt.Sprintf("failed to generate nonce: %v", err))
	}
	return nonce
}
