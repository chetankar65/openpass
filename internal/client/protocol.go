package client

import (
	"errors"
	"fmt"
)

// ProtocolVersion is the wire contract between clients and the daemon. Bump it
// whenever an existing method's request or response shape changes in a way an
// older peer would get wrong.
//
// Adding a new method does not need a bump: a peer that lacks it reports
// method-not-found, which is already a clear answer.
const ProtocolVersion = 1

var (
	// ErrDaemonOutdated means a daemon from an older build is still running.
	// This is the common case, because the daemon is long-lived: it keeps
	// serving across an upgrade until something stops it.
	ErrDaemonOutdated = errors.New("the running openpassd is older than this client")

	// ErrClientOutdated means the daemon is newer than this binary.
	ErrClientOutdated = errors.New("this client is older than the running openpassd")
)

// Hello is the daemon's self-description, available before authentication.
type Hello struct {
	Protocol int    `json:"protocol"`
	Version  string `json:"version"`
}

// Handshake checks that this client and the daemon speak the same protocol.
//
// It must run before anything else, including pairing: if the daemon predates
// pairing entirely, "unknown method client.pair" is the symptom and version
// skew is the cause.
func (c *Client) Handshake() error {
	var h Hello
	err := c.call("hello", nil, &h)

	// A daemon old enough to lack `hello` is, by definition, too old.
	if IsCode(err, CodeMethodUnknown) {
		return ErrDaemonOutdated
	}
	if err != nil {
		return err
	}

	switch {
	case h.Protocol < ProtocolVersion:
		return fmt.Errorf("%w (daemon protocol %d, this client speaks %d)",
			ErrDaemonOutdated, h.Protocol, ProtocolVersion)
	case h.Protocol > ProtocolVersion:
		return fmt.Errorf("%w (daemon protocol %d, this client speaks %d)",
			ErrClientOutdated, h.Protocol, ProtocolVersion)
	}
	return nil
}

// OutdatedAdvice turns a version-skew error into something the user can act on.
func OutdatedAdvice(err error) string {
	switch {
	case errors.Is(err, ErrDaemonOutdated):
		return fmt.Sprintf("%v.\n\nStop it and try again; a new one starts automatically:\n  pkill openpassd", err)
	case errors.Is(err, ErrClientOutdated):
		return fmt.Sprintf("%v.\n\nRebuild the client, or stop the daemon to downgrade it:\n  pkill openpassd", err)
	default:
		return err.Error()
	}
}
