package cli

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestGeneratePasswordLength(t *testing.T) {
	for _, n := range []int{8, 16, 24, 64} {
		pw, err := generatePassword(n)
		if err != nil {
			t.Fatalf("generatePassword(%d) failed: %v", n, err)
		}
		if len(pw) != n {
			t.Errorf("generatePassword(%d) returned %d characters", n, len(pw))
		}
		for i, b := range pw {
			if !strings.ContainsRune(passwordAlphabet, rune(b)) {
				t.Errorf("character %d (%q) is not in the alphabet", i, b)
			}
		}
	}

	if _, err := generatePassword(4); err == nil {
		t.Error("generatePassword accepted a length below the minimum")
	}
}

// Two generated passwords must never match. A failure here means the RNG is
// not being used, which would be silent and total.
func TestGeneratePasswordIsRandom(t *testing.T) {
	seen := make(map[string]bool, 64)
	for i := 0; i < 64; i++ {
		pw, err := generatePassword(24)
		if err != nil {
			t.Fatal(err)
		}
		if seen[string(pw)] {
			t.Fatalf("generatePassword repeated a value after %d draws", i)
		}
		seen[string(pw)] = true
	}
}

// Every character must be reachable. A bug in the index arithmetic could
// quietly shrink the alphabet and cost entropy without changing the length.
func TestGeneratePasswordCoversAlphabet(t *testing.T) {
	seen := map[byte]bool{}
	for i := 0; i < 400; i++ {
		pw, err := generatePassword(32)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range pw {
			seen[b] = true
		}
	}

	for i := 0; i < len(passwordAlphabet); i++ {
		if !seen[passwordAlphabet[i]] {
			t.Errorf("character %q never appeared", passwordAlphabet[i])
		}
	}
}

// The alphabet must exclude characters that are easy to confuse when a
// password has to be read aloud or retyped.
func TestPasswordAlphabetExcludesAmbiguousCharacters(t *testing.T) {
	for _, c := range []rune{'0', 'O', 'l', '1', 'I'} {
		if strings.ContainsRune(passwordAlphabet, c) {
			t.Errorf("alphabet contains the ambiguous character %q", c)
		}
	}
}

func TestSplitList(t *testing.T) {
	cases := map[string][]string{
		"":                    nil,
		"a":                   {"a"},
		"a,b":                 {"a", "b"},
		" a , b ":             {"a", "b"},
		"a,,b":                {"a", "b"},
		"https://x,https://y": {"https://x", "https://y"},
	}

	for in, want := range cases {
		got := splitList(in)
		if len(got) != len(want) {
			t.Errorf("splitList(%q) = %v, want %v", in, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("splitList(%q) = %v, want %v", in, got, want)
				break
			}
		}
	}
}

// parseArgs must accept flags on either side of the positional argument.
// Go's flag package stops at the first non-flag, so without this
// `add GitHub -user me` silently drops the flags.
func TestParseArgsAcceptsFlagsAfterPositionals(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"flags first", []string{"-user", "chetan", "-gen", "GitHub"}},
		{"flags last", []string{"GitHub", "-user", "chetan", "-gen"}},
		{"interleaved", []string{"-user", "chetan", "GitHub", "-gen"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := newTestFlagSet()
			user := fs.String("user", "", "")
			gen := fs.Bool("gen", false, "")

			positional, err := parseArgs(fs, tc.args)
			if err != nil {
				t.Fatalf("parseArgs failed: %v", err)
			}

			if len(positional) != 1 || positional[0] != "GitHub" {
				t.Errorf("positional = %v, want [GitHub]", positional)
			}
			if *user != "chetan" {
				t.Errorf("-user = %q, want chetan", *user)
			}
			if !*gen {
				t.Error("-gen was not set")
			}
		})
	}
}

func TestParseArgsRejectsUnknownFlag(t *testing.T) {
	fs := newTestFlagSet()
	if _, err := parseArgs(fs, []string{"GitHub", "-nope"}); err == nil {
		t.Error("parseArgs accepted an undefined flag")
	}
}

func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(&bytes.Buffer{})
	return fs
}
