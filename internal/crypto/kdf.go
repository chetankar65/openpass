package crypto

import (
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// MinSaltLength is the smallest salt DeriveKey will accept.
const MinSaltLength = 16

type Argon2Params struct {
	Time        uint32 `json:"t"`
	Memory      uint32 `json:"m_kib"`
	Parallelism uint8  `json:"p"`
}

// DefaultArgon2Params returns the parameters from DESIGN.md §3.2 — the RFC 9106
// second recommended profile.
func DefaultArgon2Params() *Argon2Params {
	return &Argon2Params{
		Time:        3,
		Memory:      64 * 1024, // KiB
		Parallelism: 4,
	}
}

// DeriveKey derives a key from the given password and salt using Argon2id.
func (p *Argon2Params) DeriveKey(password, salt []byte) ([]byte, error) {
	if len(salt) < MinSaltLength {
		return nil, fmt.Errorf("salt must be at least %d bytes, got %d", MinSaltLength, len(salt))
	}
	return argon2.IDKey(password, salt, p.Time, p.Memory, p.Parallelism, chacha20poly1305.KeySize), nil
}

// Tune overrides the cost parameters, for tuning against the local machine at
// vault creation time.
func (p *Argon2Params) Tune(time, memory uint32, parallelism uint8) {
	p.Time = time
	p.Memory = memory
	p.Parallelism = parallelism
}
