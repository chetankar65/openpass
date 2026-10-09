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
	"sync"
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
	Jsonrpc string          `json:"jsonrpc"`
	Id      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Auth    *Auth           `json:"auth,omitempty"`
}

type response struct {
	Jsonrpc string          `json:"jsonrpc"`
	Id      *int            `json:"id"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Notification is a message the daemon sends unprompted. In JSON-RPC these
// carry no id, which is how they are told apart from replies.
type Notification struct {
	Method string
	Params json.RawMessage
}

// Client is a connection to the daemon.
type Client struct {
	mu       sync.Mutex
	conn     net.Conn
	enc      *json.Encoder
	dec      *json.Decoder
	nextID   int
	identity *Identity

	// notifications is non-nil once Notifications has been called. Until then
	// an unprompted message is a protocol error, not something to buffer.
	notifications chan Notification
}

// Notifications returns the channel of unprompted daemon messages. Call it
// before any request that could cause one.
func (c *Client) Notifications() <-chan Notification {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.notifications == nil {
		c.notifications = make(chan Notification, 8)
	}
	return c.notifications
}

// SetIdentity makes the client sign its requests.
func (c *Client) SetIdentity(id *Identity) { c.identity = id }

func (c *Client) Identity() *Identity { return c.identity }

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

// readResponse reads until the reply to id arrives, routing any notifications
// that turn up in between.
func (c *Client) readResponse(id int) (*response, error) {
	for {
		var resp response
		if err := c.dec.Decode(&resp); err != nil {
			return nil, err
		}

		if resp.Id == nil {
			c.deliver(Notification{Method: resp.Method, Params: resp.Params})
			continue
		}
		if *resp.Id != id {
			return nil, fmt.Errorf("response id %d does not match request id %d", *resp.Id, id)
		}
		return &resp, nil
	}
}

// ReadNotification blocks until the daemon sends one. Only for connections
// doing nothing else, such as a subscriber.
func (c *Client) ReadNotification() (Notification, error) {
	for {
		var resp response
		if err := c.dec.Decode(&resp); err != nil {
			return Notification{}, err
		}
		if resp.Id == nil {
			return Notification{Method: resp.Method, Params: resp.Params}, nil
		}
	}
}

// deliver hands a notification to the subscriber, dropping it if nobody is
// listening or the buffer is full. A slow subscriber must not stall requests.
func (c *Client) deliver(n Notification) {
	c.mu.Lock()
	ch := c.notifications
	c.mu.Unlock()

	if ch == nil {
		return
	}
	select {
	case ch <- n:
	default:
	}
}

// call sends one request and decodes the reply into out.
func (c *Client) call(method string, params, out any) error {
	c.nextID++
	id := c.nextID

	var raw json.RawMessage
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("failed to encode params for %s: %w", method, err)
		}
		raw = encoded
	}

	req := request{Jsonrpc: "2.0", Id: id, Method: method, Params: raw}

	// Signed with the exact bytes that go on the wire, so the daemon verifies
	// what it actually received.
	if c.identity != nil {
		auth, err := c.identity.Sign(method, raw)
		if err != nil {
			return err
		}
		req.Auth = auth
	}

	if err := c.enc.Encode(req); err != nil {
		return fmt.Errorf("failed to send %s: %w", method, err)
	}

	resp, err := c.readResponse(id)
	if err != nil {
		return fmt.Errorf("failed to read the response to %s: %w", method, err)
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
