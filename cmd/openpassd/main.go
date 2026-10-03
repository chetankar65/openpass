package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/chetankar/openpass/internal/daemon"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine the home directory: %v", err)
	}
	base := filepath.Join(home, ".openpass")

	vaultPath := flag.String("vault", filepath.Join(base, "vault.opv"), "path to the vault file")
	socketPath := flag.String("socket", filepath.Join(base, "run", "openpassd.sock"), "path to the unix socket")
	idleTimeout := flag.Duration("autolock", daemon.DefaultIdleTimeout,
		"lock the vault after this long without use; 0 disables autolock")
	flag.Parse()

	// The daemon runs in the foreground and is backgrounded by whatever starts
	// it — launchd, or a shell. Self-daemonising in Go means fork/exec games
	// that a supervisor already does better.
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("openpassd: ")

	// NewServer takes the vault flock, so a second daemon fails here rather
	// than racing for the file.
	server, err := daemon.NewServer(*socketPath, *vaultPath, *idleTimeout)
	if err != nil {
		log.Fatalf("startup failed: %v", err)
	}

	if err := server.Listen(); err != nil {
		server.Close()
		log.Fatalf("startup failed: %v", err)
	}

	daemon.SetupGracefulShutdown(server)

	log.Printf("vault: %s", *vaultPath)
	if *idleTimeout > 0 {
		log.Printf("autolock: %s", *idleTimeout)
	} else {
		log.Printf("autolock: disabled")
	}
	if err := server.Serve(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
