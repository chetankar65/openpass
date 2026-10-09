package daemon

import (
	"errors"
	"net"
	"testing"

	"github.com/chetankar/openpass/internal/client"
)

// hello must work before pairing, or a client could never learn why its first
// real call failed.
func TestHelloNeedsNoAuth(t *testing.T) {
	s, _ := startServer(t)

	c, err := client.Dial(s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// No identity set: this request is unsigned.
	if err := c.Handshake(); err != nil {
		t.Fatalf("Handshake failed without an identity: %v", err)
	}
}

func TestHandshakeAcceptsMatchingProtocol(t *testing.T) {
	s, dir := startServer(t)
	c, _ := dialAs(t, s, dir, "cli", "cli")

	if err := c.Handshake(); err != nil {
		t.Errorf("Handshake failed against its own daemon: %v", err)
	}
}

// A daemon old enough to lack `hello` must be reported as outdated rather than
// as some confusing downstream failure.
func TestHandshakeDetectsPreHelloDaemon(t *testing.T) {
	socket := shortSocketPath(t)

	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Stand in for an old daemon: it answers, but knows no methods.
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"unknown method \"hello\""}}` + "\n"))
		<-make(chan struct{})
	}()

	c, err := client.Dial(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	err = c.Handshake()
	if !errors.Is(err, client.ErrDaemonOutdated) {
		t.Fatalf("err = %v, want ErrDaemonOutdated", err)
	}

	// The message has to say what to do about it.
	advice := client.OutdatedAdvice(err)
	if !contains(advice, "pkill openpassd") {
		t.Errorf("advice does not say how to fix it: %s", advice)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
