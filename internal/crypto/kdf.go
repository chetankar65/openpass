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

// Validate rejects parameter sets that argon2 refuses.
//
// This matters because parameters are read from the vault header, which is
// attacker-modifiable and parsed before anything has been authenticated:
// argon2.IDKey panics on time < 1 or parallelism < 1, so an unvalidated header
// is a remote crash once the daemon exists.
//
// Note this is a liveness check, not a strength check — it does not enforce the
// DESIGN.md §3.2 floors. Enforcing those on read would refuse to open a vault
// that was legitimately created with lower parameters.
func (p *Argon2Params) Validate() error {
	if p.Time < 1 {
		return fmt.Errorf("argon2 time must be at least 1, got %d", p.Time)
	}
	if p.Parallelism < 1 {
		return fmt.Errorf("argon2 parallelism must be at least 1, got %d", p.Parallelism)
	}
	if p.Memory < 8*uint32(p.Parallelism) {
		return fmt.Errorf("argon2 memory must be at least %d KiB for %d threads, got %d",
			8*uint32(p.Parallelism), p.Parallelism, p.Memory)
	}
	return nil
}

// DeriveKey derives a key from the given password and salt using Argon2id.
func (p *Argon2Params) DeriveKey(password, salt []byte) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
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
