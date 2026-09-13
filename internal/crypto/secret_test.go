package crypto

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSecret(t *testing.T) {
	// Create a new secret
	secretData := []byte("my_secret_password")
	secret := SetSecret(secretData)

	// Ensure the secret is stored correctly
	if !bytes.Equal(secret.GetSecret(), secretData) {
		t.Errorf("Expected secret %s, got %s", secretData, secret.GetSecret())
	}

	// Clear the secret and ensure it's released
	secret.ClearSecret()
	if len(secret.GetSecret()) != 0 {
		t.Errorf("Expected cleared secret to be empty, got %d bytes", len(secret.GetSecret()))
	}
}

// SetSecret must copy, not alias: clearing the Secret must leave the caller's
// slice untouched.
func TestSetSecretCopies(t *testing.T) {
	original := []byte("my_secret_password")
	secret := SetSecret(original)

	secret.ClearSecret()

	if !bytes.Equal(original, []byte("my_secret_password")) {
		t.Errorf("SetSecret aliased the caller's slice; it now reads %q", original)
	}
}

// ClearSecret must actually zero the bytes, not just drop the slice. Capturing
// the buffer first is what makes this fail if the zeroing loop is removed.
func TestClearSecretZeroes(t *testing.T) {
	secret := SetSecret([]byte("my_secret_password"))
	buf := secret.GetSecret()

	secret.ClearSecret()

	for i, b := range buf {
		if b != 0 {
			t.Fatalf("byte %d was not zeroed: %#x", i, b)
		}
	}
}

func TestClearSecretIsIdempotent(t *testing.T) {
	secret := SetSecret([]byte("my_secret_password"))
	secret.ClearSecret()
	secret.ClearSecret() // must not panic
}

// A Secret must never render its contents, whatever the verb, and whether it is
// formatted directly or as a field of an enclosing struct.
func TestSecretIsRedacted(t *testing.T) {
	const plaintext = "my_secret_password"
	secret := SetSecret([]byte(plaintext))
	defer secret.ClearSecret()

	enclosing := struct{ Password Secret }{Password: *secret}

	for _, out := range []string{
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%s", secret),
		fmt.Sprintf("%q", secret),
		fmt.Sprintf("%#v", secret),
		fmt.Sprintf("%+v", enclosing),
	} {
		if bytes.Contains([]byte(out), []byte(plaintext)) {
			t.Errorf("Secret leaked its contents: %s", out)
		}
	}
}
