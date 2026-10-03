// Package client speaks the daemon's JSON-RPC protocol over a Unix socket.
//
// It exists because the vault lives in another process: its whole job is making
// "send a request and wait for a reply" look like an ordinary method call. It
// holds no vault state, does no crypto, and never touches the vault file.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Wire error codes from docs/API.md.
const (
	CodeInvalidParams = -32602
	CodeMethodUnknown = -32601
	CodeVaultLocked   = -32001
	CodeBadPassword   = -32002
	CodeNotFound      = -32003
	CodeVaultExists   = -32008
	CodeStorage       = -32009
)

// Error is a JSON-RPC error from the daemon.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Message }

// IsCode reports whether err is a daemon error with the given code. Callers use
// this instead of comparing strings — in particular, the CLI has to recognise
// CodeVaultLocked to prompt for a password and retry.
func IsCode(err error, code int) bool {
	var rpcErr *Error
	return errors.As(err, &rpcErr) && rpcErr.Code == code
}

type request struct {
	Jsonrpc string `json:"jsonrpc"`
	Id      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

type response struct {
	Jsonrpc string          `json:"jsonrpc"`
	Id      int             `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Client is a connection to the daemon.
type Client struct {
	conn   net.Conn
	enc    *json.Encoder
	dec    *json.Decoder
	nextID int
}

// Dial connects to the daemon at socketPath.
func Dial(socketPath string) (*Client, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	return &Client{
		conn: conn,
		enc:  json.NewEncoder(conn),
		dec:  json.NewDecoder(conn),
	}, nil
}

// DialOrSpawn connects to the daemon, starting it if it is not running.
//
// The daemon is detached so it outlives this process — the point of a daemon is
// that the next `openpass get` does not have to type a password again.
func DialOrSpawn(socketPath, vaultPath, daemonBin string) (*Client, error) {
	c, err := Dial(socketPath)
	if err == nil {
		return c, nil
	}

	if err := spawnDaemon(daemonBin, socketPath, vaultPath); err != nil {
		return nil, fmt.Errorf("the daemon is not running and could not be started: %w", err)
	}

	// Retry while the daemon creates its socket. One retry only — if the second
	// attempt fails, something is actually wrong and looping would just hide it.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := Dial(socketPath); err == nil {
			return c, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("started the daemon but could not connect to %s", socketPath)
}

func spawnDaemon(bin, socketPath, vaultPath string) error {
	if bin == "" {
		return errors.New("no openpassd binary found on PATH")
	}

	cmd := exec.Command(bin, "-socket", socketPath, "-vault", vaultPath)
	// Detach: no stdin, and output discarded so the daemon does not scribble
	// over the CLI's terminal.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	// Do not Wait: we want it to keep running. Release lets this process exit
	// without leaving a zombie behind.
	return cmd.Process.Release()
}

// FindDaemonBinary looks for openpassd next to the running binary first, then
// on PATH. Next-to-first means a locally built pair works without installing.
func FindDaemonBinary() string {
	if self, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(self), "openpassd")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	if path, err := exec.LookPath("openpassd"); err == nil {
		return path
	}
	return ""
}

func (c *Client) Close() error { return c.conn.Close() }

// call sends one request and decodes the reply into out.
func (c *Client) call(method string, params, out any) error {
	c.nextID++
	id := c.nextID

	if err := c.enc.Encode(request{Jsonrpc: "2.0", Id: id, Method: method, Params: params}); err != nil {
		return fmt.Errorf("failed to send %s: %w", method, err)
	}

	var resp response
	if err := c.dec.Decode(&resp); err != nil {
		return fmt.Errorf("failed to read the response to %s: %w", method, err)
	}
	if resp.Id != id {
		return fmt.Errorf("response id %d does not match request id %d", resp.Id, id)
	}
	if resp.Error != nil {
		return resp.Error
	}
	if out != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("failed to parse the result of %s: %w", method, err)
		}
	}
	return nil
}
