// Command openpass-bridge relays Chrome native messaging to the openpass
// daemon.
//
// The browser launches this as a subprocess and speaks 4-byte-length-prefixed
// JSON over stdin/stdout. Everything here is relay and plumbing: no crypto, no
// vault access, no policy. Which extension may launch it is enforced by the
// browser, via allowed_origins in the native messaging manifest.
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/chetankar/openpass/internal/client"
)

// maxMessage caps what we will read from the browser. Chrome's own limit is
// 64 MB inbound; anything near that is a bug or an attack.
const maxMessage = 1 << 20

type incoming struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type outgoing struct {
	ID     int    `json:"id"`
	Result any    `json:"result,omitempty"`
	Error  *rpcEr `json:"error,omitempty"`
}

type rpcEr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine the home directory: %v", err)
	}
	base := filepath.Join(home, ".openpass")

	vaultPath := flag.String("vault", filepath.Join(base, "vault.opv"), "vault file path")
	socketPath := flag.String("socket", filepath.Join(base, "run", "openpassd.sock"), "daemon socket path")
	identityPath := flag.String("identity", filepath.Join(base, "bridge.key"), "bridge identity key path")
	flag.Parse()

	// Logs must not go to stdout: that channel carries framed messages to the
	// browser and a stray line corrupts the stream.
	log.SetOutput(os.Stderr)
	log.SetPrefix("openpass-bridge: ")

	b := &bridge{
		vaultPath:    *vaultPath,
		socketPath:   *socketPath,
		identityPath: *identityPath,
	}

	if err := b.run(os.Stdin, os.Stdout); err != nil && !errors.Is(err, io.EOF) {
		log.Printf("exiting: %v", err)
		os.Exit(1)
	}
}

type bridge struct {
	vaultPath    string
	socketPath   string
	identityPath string
}

func (b *bridge) run(in io.Reader, out io.Writer) error {
	for {
		msg, err := readMessage(in)
		if err != nil {
			return err
		}

		var req incoming
		if err := json.Unmarshal(msg, &req); err != nil {
			writeMessage(out, outgoing{Error: &rpcEr{Code: -32700, Message: "malformed request"}})
			continue
		}

		resp := b.handle(req)
		if err := writeMessage(out, resp); err != nil {
			return err
		}
	}
}

// handle opens a fresh connection per message.
//
// Manifest V3 kills the extension's service worker after about 30 seconds idle
// and takes this process with it, so there is no long-lived connection to hold.
// The daemon keeps the session, not the socket, so reconnecting costs nothing.
func (b *bridge) handle(req incoming) outgoing {
	c, err := client.DialOrSpawn(b.socketPath, b.vaultPath, client.FindDaemonBinary())
	if err != nil {
		return outgoing{ID: req.ID, Error: &rpcEr{Code: -32000, Message: fmt.Sprintf("cannot reach the daemon: %v", err)}}
	}
	defer c.Close()

	identity, err := client.LoadOrCreateIdentity(b.identityPath, "Browser extension", "browser")
	if err != nil {
		return outgoing{ID: req.ID, Error: &rpcEr{Code: -32000, Message: err.Error()}}
	}
	c.SetIdentity(identity)

	pair, err := c.Pair()
	if err != nil {
		return outgoing{ID: req.ID, Error: &rpcEr{Code: -32000, Message: err.Error()}}
	}

	// Surface the pairing code so the extension can show it. Until a human
	// approves, nothing else will work.
	if pair.State != "approved" {
		return outgoing{ID: req.ID, Error: &rpcEr{
			Code:    -32005,
			Message: fmt.Sprintf("not approved yet. Run: openpass client approve %s", pair.Code),
		}}
	}

	result, rerr := b.proxy(c, req)
	if rerr != nil {
		return outgoing{ID: req.ID, Error: rerr}
	}
	return outgoing{ID: req.ID, Result: result}
}

func (b *bridge) proxy(c *client.Client, req incoming) (any, *rpcEr) {
	switch req.Method {
	case "status":
		s, err := c.Status()
		return s, toErr(err)

	case "vault.match":
		var p struct {
			URL string `json:"url"`
		}
		json.Unmarshal(req.Params, &p)
		r, err := c.Match(p.URL, false)
		return r, toErr(err)

	case "vault.get":
		var p struct {
			ID     string `json:"id"`
			Reveal bool   `json:"reveal"`
		}
		json.Unmarshal(req.Params, &p)
		e, err := c.Get(p.ID, p.Reveal)
		return e, toErr(err)

	default:
		// The daemon enforces this too; refusing here keeps unknown methods
		// from reaching it at all.
		return nil, &rpcEr{Code: -32601, Message: "method not available over the bridge: " + req.Method}
	}
}

func toErr(err error) *rpcEr {
	if err == nil {
		return nil
	}

	var rpcErr *client.Error
	if errors.As(err, &rpcErr) {
		return &rpcEr{Code: rpcErr.Code, Message: rpcErr.Message}
	}
	return &rpcEr{Code: -32000, Message: err.Error()}
}

// readMessage reads one native-messaging frame: a 4-byte native-endian length
// followed by that many bytes of JSON.
func readMessage(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	length := binary.LittleEndian.Uint32(header[:])
	if length == 0 || length > maxMessage {
		return nil, fmt.Errorf("message length %d is out of range", length)
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeMessage(w io.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}

	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(data)))

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}
