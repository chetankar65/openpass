package crypto

import (
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Seal encrypts and authenticates plaintext, additionally authenticating
// additionalData, and returns the ciphertext with the 16-byte tag appended.

func Seal(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", chacha20poly1305.NonceSizeX, len(nonce))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

// Open authenticates and decrypts ciphertext, and returns the plaintext.

func Open(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", chacha20poly1305.NonceSizeX, len(nonce))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("failed to open AEAD: %v", err)
	}

	return plaintext, nil
}
