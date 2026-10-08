package cli

import (
	"errors"
	"flag"
	"fmt"
	"text/tabwriter"

	"github.com/chetankar/openpass/internal/client"
)

const clientUsage = `Usage:
  openpass client ls
  openpass client approve <code>
  openpass client revoke <id>
  openpass client pair <name> [-kind browser] [-key <path>]
`

func (a *app) cmdClient(args []string) error {
	if len(args) == 0 {
		return errors.New(clientUsage)
	}

	switch args[0] {
	case "ls", "list":
		return a.clientList()
	case "approve":
		return a.clientApprove(args[1:])
	case "revoke":
		return a.clientRevoke(args[1:])
	case "pair":
		return a.clientPair(args[1:])
	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], clientUsage)
	}
}

func (a *app) clientList() error {
	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	records, err := c.ListClients()
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tKIND\tSTATE\tREVEAL")
	for _, r := range records {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.Name, r.Kind, r.State, r.Policy.Reveal)
	}
	return tw.Flush()
}

func (a *app) clientApprove(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: openpass client approve <code>")
	}

	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	record, err := c.ApproveClient(args[0])
	if err != nil {
		return err
	}

	fmt.Fprintf(a.stdout, "Approved %s (%s)\n", record.Name, record.ID)
	return nil
}

func (a *app) clientRevoke(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: openpass client revoke <id>")
	}

	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.RevokeClient(args[0]); err != nil {
		return err
	}

	fmt.Fprintf(a.stdout, "Revoked %s\n", args[0])
	return nil
}

// clientPair registers a new identity. This is the exact path the browser
// bridge will take: generate a key, call client.pair, show the code.
func (a *app) clientPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	kind := fs.String("kind", "browser", "client kind: browser, cli, or other")
	keyPath := fs.String("key", "", "where to write the identity (default alongside the vault)")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: openpass client pair <name> [-kind browser] [-key <path>]")
	}
	name := positional[0]

	path := *keyPath
	if path == "" {
		path = a.identityPath + "." + *kind
	}

	identity, err := client.LoadOrCreateIdentity(path, name, *kind)
	if err != nil {
		return err
	}

	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetIdentity(identity)

	result, err := c.Pair()
	if err != nil {
		return err
	}

	fmt.Fprintf(a.stdout, "Client %s (%s)\n", identity.ID, path)
	if result.State == "approved" {
		fmt.Fprintln(a.stdout, "Approved automatically as the first client.")
		return nil
	}

	fmt.Fprintf(a.stdout, "\nApprove it with:\n  openpass client approve %s\n", result.Code)
	fmt.Fprintln(a.stdout, "\nThe code expires in 2 minutes.")
	return nil
}
