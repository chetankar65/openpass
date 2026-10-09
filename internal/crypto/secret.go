package crypto

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	"golang.org/x/sys/unix"
)

type Secret struct {
	// The secret is stored in memory as a byte slice
	Data []byte
	// Whether mlock succeeded. Failure (RLIMIT_MEMLOCK) is not fatal — the
	locked bool
}

// SetSecret copies data into a new Secret and locks it into memory for the
// Secret's lifetime.
func SetSecret(data []byte) *Secret {
	s := &Secret{Data: make([]byte, len(data))}
	copy(s.Data, data)
	s.locked = s.mlock() == nil
	return s
}

// Zero overwrites b in place. It is the wipe every caller outside this package
// should use — the CLI on a password buffer, the daemon on a decoded request.
//
// Best effort: Go has no explicit_bzero, and KeepAlive is the closest thing to
// an optimisation barrier available.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// GetSecret returns the underlying bytes without copying. The slice is valid
// only until ClearSecret is called.
func (s *Secret) GetSecret() []byte {
	return s.Data
}

// ClearSecret zeroes the secret in memory, unlocks it, and releases the slice.
// It is safe to call more than once.
func (s *Secret) ClearSecret() {
	for i := range s.Data {
		s.Data[i] = 0
	}
	// Without this the zeroing loop is, in principle, eliminable as dead stores.
	runtime.KeepAlive(s.Data)

	if s.locked {
		s.munlock()
		s.locked = false
	}
	s.Data = nil
}

// MarshalJSON emits the secret's bytes, base64-encoded per encoding/json's
// convention for []byte.
//
// This is the one place a Secret is allowed to render its contents, and it
// exists for exactly one caller: serializing the vault body, which is encrypted
// immediately afterwards. Nothing containing a Secret may be marshalled into
// anything that leaves the process — API responses use their own wire types,
// see docs/API.md. Note the asymmetry with Format: fmt redacts, JSON does not.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.Data)
}

// UnmarshalJSON reads bytes into a new locked buffer and zeroes the
// intermediate that encoding/json produced.
func (s *Secret) UnmarshalJSON(b []byte) error {
	var data []byte
	if err := json.Unmarshal(b, &data); err != nil {
		return fmt.Errorf("failed to unmarshal secret: %v", err)
	}

	s.Data = make([]byte, len(data))
	copy(s.Data, data)
	s.locked = s.mlock() == nil

	for i := range data {
		data[i] = 0
	}
	runtime.KeepAlive(data)
	return nil
}

// Format renders a Secret as "[redacted]" for every verb, so a stray %v, %s or
// %#v cannot leak it into a log or a panic trace.
func (s Secret) Format(f fmt.State, verb rune) {
	io.WriteString(f, "[redacted]")
}

// mlock keeps the secret's pages out of swap, so it cannot be written to disk
// in a swapfile or hibernation image.
//
// mlock operates on whole pages, so this locks the page(s) containing data,
// which will also hold unrelated heap objects. Locking a page-aligned mmap
// rather than a GC-heap slice would be exact; this is the cheap approximation.
func (s *Secret) mlock() error {
	if len(s.Data) == 0 {
		return fmt.Errorf("cannot mlock an empty secret")
	}
	return unix.Mlock(s.Data)
}

// munlock allows the OS to swap the memory to disk again.
func (s *Secret) munlock() error {
	if len(s.Data) == 0 {
		return fmt.Errorf("cannot munlock an empty secret")
	}
	return unix.Munlock(s.Data)
}
