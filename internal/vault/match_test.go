package vault

import (
	"errors"
	"testing"
)

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"https://github.com":             "github.com",
		"https://github.com/login":       "github.com",
		"https://login.github.com":       "github.com",
		"https://a.b.c.github.com/x?y=z": "github.com",
		"github.com":                     "github.com",
		"https://GitHub.COM":             "github.com",
		"https://github.com.":            "github.com",
		"https://example.co.uk":          "example.co.uk",
		"https://www.example.co.uk":      "example.co.uk",
	}

	for in, want := range cases {
		got, err := RegistrableDomain(in)
		if err != nil {
			t.Errorf("RegistrableDomain(%q) failed: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

// Hosts with no registrable domain must be refused rather than guessed at.
func TestRegistrableDomainRejectsUnmatchable(t *testing.T) {
	for _, in := range []string{
		"https://localhost",
		"https://127.0.0.1",
		"https://[::1]",
		"https://192.168.1.1:8080",
		"",
		"not a url at all %%%",
	} {
		if got, err := RegistrableDomain(in); err == nil {
			t.Errorf("RegistrableDomain(%q) = %q, want an error", in, got)
		}
	}
}

var phishEntries = []Entry{
	{ID: "1", Name: "PayPal", URLs: []string{"https://paypal.com"}},
	{ID: "2", Name: "GitHub", URLs: []string{"https://github.com"}},
	{ID: "3", Name: "Bank", URLs: []string{"https://chase.com", "https://secure.chase.com"}},
	{ID: "4", Name: "No URLs"},
}

// The attacks this function exists to stop.
func TestMatchURLRejectsLookalikes(t *testing.T) {
	for _, page := range []string{
		"https://paypal.com.evil.com/login",
		"https://evil.com/paypal.com",
		"https://paypal.com.attacker.co.uk",
		"https://notpaypal.com",
		"https://paypal.evil.com",
	} {
		_, matched, err := MatchURL(phishEntries, page, MatchOptions{})
		if err != nil {
			continue
		}
		for _, e := range matched {
			if e.Name == "PayPal" {
				t.Errorf("%s matched the PayPal entry", page)
			}
		}
	}
}

func TestMatchURLSubdomainsMatch(t *testing.T) {
	domain, matched, err := MatchURL(phishEntries, "https://login.github.com/session", MatchOptions{})
	if err != nil {
		t.Fatalf("MatchURL failed: %v", err)
	}
	if domain != "github.com" {
		t.Errorf("domain = %q, want github.com", domain)
	}
	if len(matched) != 1 || matched[0].Name != "GitHub" {
		t.Errorf("matched %+v, want the GitHub entry", matched)
	}
}

// An entry with several URLs on one domain must match once, not once per URL.
func TestMatchURLDoesNotDuplicate(t *testing.T) {
	_, matched, err := MatchURL(phishEntries, "https://chase.com", MatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 1 {
		t.Errorf("matched %d entries, want 1", len(matched))
	}
}

// A public suffix is not a registrable domain: two sites under .co.uk are
// different sites.
func TestMatchURLPublicSuffixIsNotADomain(t *testing.T) {
	entries := []Entry{{ID: "1", Name: "A", URLs: []string{"https://alpha.co.uk"}}}

	_, matched, err := MatchURL(entries, "https://beta.co.uk", MatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(matched) != 0 {
		t.Errorf("beta.co.uk matched an alpha.co.uk entry: %+v", matched)
	}
}

func TestMatchURLRefusesInsecurePagesByDefault(t *testing.T) {
	if _, _, err := MatchURL(phishEntries, "http://github.com", MatchOptions{}); err == nil {
		t.Error("an http page matched without AllowInsecure")
	}
	if _, matched, err := MatchURL(phishEntries, "http://github.com", MatchOptions{AllowInsecure: true}); err != nil {
		t.Errorf("AllowInsecure did not permit http: %v", err)
	} else if len(matched) != 1 {
		t.Errorf("matched %d entries with AllowInsecure, want 1", len(matched))
	}
}

func TestMatchURLUnmatchablePage(t *testing.T) {
	_, _, err := MatchURL(phishEntries, "https://localhost:3000", MatchOptions{})
	if !errors.Is(err, ErrUnmatchableURL) {
		t.Errorf("err = %v, want ErrUnmatchableURL", err)
	}
}

func TestMatchURLNoMatches(t *testing.T) {
	domain, matched, err := MatchURL(phishEntries, "https://nowhere.example", MatchOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if domain != "nowhere.example" {
		t.Errorf("domain = %q", domain)
	}
	if len(matched) != 0 {
		t.Errorf("matched %+v, want nothing", matched)
	}
}
