package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/chetankar/openpass/internal/client"
)

// cmdWatch answers the daemon's approval questions.
//
// The daemon is headless, so without something running this, a client whose
// policy is "prompt" can never read a secret. This is that something.
func (a *app) cmdWatch(args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	ttl := fs.Int("remember", 300, "seconds to allow the same client and site after a yes; 0 asks every time")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Subscribe(); err != nil {
		return err
	}

	fmt.Fprintln(a.stderr, "Watching for approval requests. Ctrl-C to stop.")

	reader := bufio.NewReader(os.Stdin)
	for {
		note, err := c.ReadNotification()
		if err != nil {
			return fmt.Errorf("lost the connection to the daemon: %w", err)
		}
		if note.Method != "approval.requested" {
			continue
		}

		var req client.ApprovalRequest
		if err := json.Unmarshal(note.Params, &req); err != nil {
			continue
		}

		allow := a.askApproval(reader, req)
		grant := 0
		if allow {
			grant = *ttl
		}

		if err := c.Respond(req.ID, allow, grant); err != nil {
			fmt.Fprintf(a.stderr, "could not answer: %v\n", err)
		}
	}
}

func (a *app) askApproval(reader *bufio.Reader, req client.ApprovalRequest) bool {
	where := req.Domain
	if where == "" {
		where = "no site"
	}

	fmt.Fprintf(a.stderr, "\n%s wants the password for %q (%s)\nAllow? [y/N] ", req.Client, req.Entry, where)

	if !isTerminal(os.Stdin) {
		fmt.Fprintln(a.stderr, "\nno terminal to ask on; denying")
		return false
	}

	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}
