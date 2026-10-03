package cli

import (
	"os"
	"testing"
)

// withStdin replaces os.Stdin with a pipe carrying the given bytes.
func withStdin(t *testing.T, data string) {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = original; r.Close() })

	go func() {
		w.WriteString(data)
		w.Close()
	}()
}

func TestReadSecretFromStdin(t *testing.T) {
	cases := map[string]string{
		// Exactly one trailing newline is stripped, because `echo x |` adds one.
		"secret\n":   "secret",
		"secret\r\n": "secret",
		"secret":     "secret",

		// Nothing else is trimmed: a password may legitimately start or end
		// with a space, and eating it would store something else.
		" leading":    " leading",
		"trailing ":   "trailing ",
		"trailing \n": "trailing ",

		// Only ONE newline goes. A second is part of the password.
		"secret\n\n": "secret\n",

		// Internal structure is untouched.
		"two\nlines\n": "two\nlines",
	}

	for input, want := range cases {
		withStdin(t, input)

		got, err := readSecretFromStdin()
		if err != nil {
			t.Errorf("readSecretFromStdin(%q) failed: %v", input, err)
			continue
		}
		if string(got) != want {
			t.Errorf("readSecretFromStdin(%q) = %q, want %q", input, got, want)
		}
	}
}

// An empty pipe must be an error, not an entry with an empty password.
func TestReadSecretFromStdinRejectsEmpty(t *testing.T) {
	for _, input := range []string{"", "\n", "\r\n"} {
		withStdin(t, input)

		if _, err := readSecretFromStdin(); err == nil {
			t.Errorf("readSecretFromStdin(%q) accepted an empty password", input)
		}
	}
}
