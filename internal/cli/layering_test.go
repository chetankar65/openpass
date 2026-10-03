package cli_test

import (
	"os/exec"
	"strings"
	"testing"
)

// The CLI must reach the vault only through the API, never by importing the
// vault or the ciphers directly.
//
// This is an architecture test, not a unit test. It fails the moment someone
// "just quickly" imports internal/vault into a command file — which is exactly
// how a layered design rots, and here it would also give the CLI a privileged
// path the browser extension cannot reach, breaking the "one API, many
// clients" goal in DESIGN.md §1.
//
// internal/crypto is allowed for one thing only: Zero, to wipe a password
// buffer after reading it. Memory hygiene is every layer's job; ciphers are not.
func TestCLIDoesNotImportVault(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/chetankar/openpass/internal/cli").Output()
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}

	for _, dep := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(dep) == "github.com/chetankar/openpass/internal/vault" {
			t.Error("internal/cli imports internal/vault; it must go through internal/client")
		}
	}
}

// The reverse direction: internal/crypto must keep exactly one caller inside
// the vault layer, so that auditing every use of a cipher stays tractable.
func TestCryptoHasNoVaultDependency(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/chetankar/openpass/internal/crypto").Output()
	if err != nil {
		t.Fatalf("go list failed: %v", err)
	}

	for _, dep := range strings.Split(string(out), "\n") {
		dep = strings.TrimSpace(dep)
		if strings.HasPrefix(dep, "github.com/chetankar/openpass/internal/") &&
			dep != "github.com/chetankar/openpass/internal/crypto" {
			t.Errorf("internal/crypto depends on %s; it must stay a leaf", dep)
		}
	}
}
