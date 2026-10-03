package client

import (
	"errors"
	"testing"
)

var testEntries = []Entry{
	{ID: "aaaa1111", Name: "GitHub", Username: "chetan", URLs: []string{"https://github.com"}},
	{ID: "bbbb2222", Name: "Gmail", Username: "me@example.com", URLs: []string{"https://mail.google.com"}},
	{ID: "cccc3333", Name: "Gmail-work", Username: "work@example.com"},
	{ID: "dddd4444", Name: "Bank", Username: "chetan", URLs: []string{"https://chase.com"}},
}

func TestResolveExactAndPrefix(t *testing.T) {
	cases := map[string]string{
		"aaaa1111":   "aaaa1111", // exact id
		"GitHub":     "aaaa1111", // exact name
		"github":     "aaaa1111", // case-insensitive
		"Git":        "aaaa1111", // unique prefix
		"Gmail-work": "cccc3333", // exact name
		"chase":      "dddd4444", // substring of a URL
	}

	for query, want := range cases {
		got, err := resolveIn(testEntries, query)
		if err != nil {
			t.Errorf("resolve(%q) failed: %v", query, err)
			continue
		}
		if got != want {
			t.Errorf("resolve(%q) = %s, want %s", query, got, want)
		}
	}
}

// An exact name must win over a longer name that merely starts with it.
// Otherwise "Gmail" would be ambiguous the moment "Gmail-work" exists, which
// would make exact names useless.
func TestResolveExactNameBeatsPrefix(t *testing.T) {
	got, err := resolveIn(testEntries, "Gmail")
	if err != nil {
		t.Fatalf("resolve(\"Gmail\") failed: %v", err)
	}
	if got != "bbbb2222" {
		t.Errorf("resolve(\"Gmail\") = %s, want bbbb2222 (the exact match)", got)
	}
}

// An ambiguous query must be an error listing the candidates, never a guess:
// resolving to the wrong entry means filling the wrong credential.
func TestResolveAmbiguousIsAnError(t *testing.T) {
	_, err := resolveIn(testEntries, "Gm")

	var ambiguous *AmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("resolve(\"Gm\") err = %v, want AmbiguousError", err)
	}
	if len(ambiguous.Matches) != 2 {
		t.Errorf("got %d candidates, want 2", len(ambiguous.Matches))
	}
}

// "chetan" is the username on two entries, so it must not silently pick one.
func TestResolveAmbiguousUsername(t *testing.T) {
	_, err := resolveIn(testEntries, "chetan")

	var ambiguous *AmbiguousError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("resolve(\"chetan\") err = %v, want AmbiguousError", err)
	}
}

func TestResolveNotFound(t *testing.T) {
	_, err := resolveIn(testEntries, "nonexistent")

	var notFound *NotFoundError
	if !errors.As(err, &notFound) {
		t.Fatalf("err = %v, want NotFoundError", err)
	}
}

func TestIsCode(t *testing.T) {
	err := error(&Error{Code: CodeVaultLocked, Message: "vault is locked"})

	if !IsCode(err, CodeVaultLocked) {
		t.Error("IsCode did not match the locked code")
	}
	if IsCode(err, CodeNotFound) {
		t.Error("IsCode matched the wrong code")
	}
	if IsCode(errors.New("plain"), CodeVaultLocked) {
		t.Error("IsCode matched a non-daemon error")
	}
}
