package vault

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// ErrUnmatchableURL means a URL has no registrable domain to compare.
var ErrUnmatchableURL = fmt.Errorf("URL has no registrable domain")

// RegistrableDomain reduces a URL to its eTLD+1.
//
// This is the only correct way to decide whether two URLs are "the same site".
// Comparing hostnames would reject login.github.com against github.com;
// comparing suffixes would accept paypal.com.evil.com against paypal.com.
func RegistrableDomain(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnmatchableURL, err)
	}

	host := u.Hostname()
	if host == "" {
		// Bare "github.com" parses with an empty Host, so retry with a scheme.
		if u, err = url.Parse("https://" + strings.TrimSpace(rawURL)); err != nil {
			return "", fmt.Errorf("%w: %v", ErrUnmatchableURL, err)
		}
		host = u.Hostname()
	}
	if host == "" {
		return "", ErrUnmatchableURL
	}

	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// IP literals and single-label hosts like localhost have no registrable
	// domain. Treating them as their own domain would make every service on
	// localhost one site; rejecting them means no autofill there, which is the
	// safer default.
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrUnmatchableURL, host)
	}
	return domain, nil
}

// MatchOptions controls which entries count as a match.
type MatchOptions struct {
	// AllowInsecure permits matching http:// pages. Off by default: filling a
	// credential into a page that arrived over plaintext hands it to anyone on
	// the path.
	AllowInsecure bool
}

// MatchURL returns the registrable domain of rawURL and every entry registered
// against that same domain.
//
// Matching happens here rather than in any client, so that no client can invent
// its own notion of "same site".
func MatchURL(entries []Entry, rawURL string, opts MatchOptions) (string, []Entry, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrUnmatchableURL, err)
	}
	if !opts.AllowInsecure && u.Scheme != "" && u.Scheme != "https" {
		return "", nil, fmt.Errorf("%w: refusing to match a %s page", ErrUnmatchableURL, u.Scheme)
	}

	domain, err := RegistrableDomain(rawURL)
	if err != nil {
		return "", nil, err
	}

	var matched []Entry
	for _, e := range entries {
		if entryMatchesDomain(e, domain) {
			matched = append(matched, e)
		}
	}
	return domain, matched, nil
}

func entryMatchesDomain(e Entry, domain string) bool {
	for _, raw := range e.URLs {
		if d, err := RegistrableDomain(raw); err == nil && d == domain {
			return true
		}
	}
	return false
}
