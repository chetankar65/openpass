package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

/*
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "vault.get",
  "params": { "id": "3f2a...", "reveal": true }
}

{ "jsonrpc": "2.0", "id": 1, "result": { ... } }
{ "jsonrpc": "2.0", "id": 1, "error": { "code": -32001, "message": "vault is locked" } }
*/

type RequestData struct {
	Jsonrpc string          `json:"jsonrpc"`
	Id      int             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type ResponseData struct {
	Jsonrpc string     `json:"jsonrpc"`
	Id      int        `json:"id"`
	Result  any        `json:"result,omitempty"`
	Error   *ErrorData `json:"error,omitempty"`
}

type ErrorData struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server accepts connections on a Unix socket and dispatches them against a
// single Session.
type Server struct {
	socketPath string
	session    *Session
	listener   net.Listener
}

func NewServer(socketPath, vaultPath string, idleTimeout time.Duration) (*Server, error) {
	session, err := NewSession(vaultPath, idleTimeout)
	if err != nil {
		return nil, err
	}
	return &Server{socketPath: socketPath, session: session}, nil
}

// Listen creates the socket. It is separate from Serve so callers (and tests)
// know the socket exists before anything tries to connect.
func (s *Server) Listen() error {
	dir := filepath.Dir(s.socketPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// A stale socket from a previous run would make Listen fail with
	// "address already in use". The vault flock, not this file, is what stops
	// two daemons running.
	if err := os.Remove(s.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("failed to remove the existing socket: %w", err)
	}

	listener, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket: %w", err)
	}

	// Owner-only. Without this the socket is world-writable on some systems,
	// and the whole reason for choosing a socket over a localhost port is that
	// it carries filesystem permissions.
	if err := os.Chmod(s.socketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	s.listener = listener
	return nil
}

func (s *Server) Addr() string { return s.socketPath }

// Serve accepts connections until the listener is closed.
func (s *Server) Serve() error {
	log.Printf("listening on %s", s.socketPath)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// A closed listener is a normal shutdown, not a failure.
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			log.Printf("accept failed: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

// Close shuts down the listener, locks the vault and releases the file lock.
func (s *Server) Close() error {
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
	return s.session.Close()
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Same-user check. This proves "same UID", not "the client I meant" — a
	// real client identity needs the pairing flow in DESIGN.md §7.4, which is
	// not built yet.
	if err := checkPeerUID(conn); err != nil {
		log.Printf("rejecting connection: %v", err)
		return
	}

	decoder := json.NewDecoder(conn)
	encoder := json.NewEncoder(conn)

	for {
		var request RequestData
		if err := decoder.Decode(&request); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("failed to decode request: %v", err)
			}
			return
		}

		// Never log params: they carry passwords.
		log.Printf("request id=%d method=%s", request.Id, request.Method)

		response := ResponseData{Jsonrpc: "2.0", Id: request.Id}
		result, rerr := s.session.Dispatch(request)
		if rerr != nil {
			response.Error = &ErrorData{Code: rerr.Code, Message: rerr.Message}
			log.Printf("request id=%d failed: %d %s", request.Id, rerr.Code, rerr.Message)
		} else {
			response.Result = result
		}

		if err := encoder.Encode(response); err != nil {
			log.Printf("failed to encode response: %v", err)
			return
		}
	}
}

// checkPeerUID rejects any connection from a different user.
func checkPeerUID(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("connection is not a unix socket")
	}

	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to access the connection: %w", err)
	}

	var peerUID uint32
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			sockErr = err
			return
		}
		peerUID = cred.Uid
	}); err != nil {
		return fmt.Errorf("failed to read peer credentials: %w", err)
	}
	if sockErr != nil {
		return fmt.Errorf("failed to read peer credentials: %w", sockErr)
	}

	if uid := uint32(os.Getuid()); peerUID != uid {
		return fmt.Errorf("peer uid %d does not match daemon uid %d", peerUID, uid)
	}
	return nil
}

// SetupGracefulShutdown locks the vault and removes the socket on SIGINT or
// SIGTERM, rather than leaving the DEK in a core dump and a stale socket
// behind.
func SetupGracefulShutdown(s *Server) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("received %s, locking the vault and shutting down", sig)
		s.Close()
		os.Exit(0)
	}()
}

// newID returns a random identifier for a new entry.
func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("failed to generate an id: %v", err))
	}
	return hex.EncodeToString(b)
}
