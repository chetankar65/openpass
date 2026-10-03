// Package cli implements the openpass command-line interface.
//
// It owns flags, prompts, the clipboard and exit codes. It deliberately does
// not import internal/crypto or internal/vault: everything it knows about the
// vault, it learns over the API, which keeps the CLI from becoming a privileged
// path the browser extension cannot reach.
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/chetankar/openpass/internal/client"
	"github.com/chetankar/openpass/internal/crypto"
)

// Exit codes. Scripts need to tell "locked" from "no such entry", so these are
// part of the interface, not an afterthought.
const (
	ExitOK        = 0
	ExitError     = 1
	ExitLocked    = 2
	ExitNotFound  = 3
	ExitAmbiguous = 4
)

type app struct {
	socketPath string
	vaultPath  string
	stdout     io.Writer
	stderr     io.Writer
}

const usage = `openpass — a local password manager

Usage:
  openpass <command> [flags] [args]

Commands:
  init                 create a new vault and set the master password
  unlock               unlock the vault
  lock                 lock the vault
  status               show whether the vault exists and is unlocked
  ls                   list entries (never shows secrets)
  add <name>           add an entry
  get <name|id>        read an entry's password
  rm <name|id>         delete an entry

Global flags:
  -socket <path>       daemon socket (default ~/.openpass/run/openpassd.sock)
  -vault <path>        vault file, used when starting the daemon

Run "openpass <command> -h" for a command's flags.
`

// Main runs the CLI and returns a process exit code.
func Main(args []string) int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openpass: cannot determine the home directory: %v\n", err)
		return ExitError
	}
	base := filepath.Join(home, ".openpass")

	a := &app{
		socketPath: filepath.Join(base, "run", "openpassd.sock"),
		vaultPath:  filepath.Join(base, "vault.opv"),
		stdout:     os.Stdout,
		stderr:     os.Stderr,
	}

	// Global flags may appear before the command.
	global := flag.NewFlagSet("openpass", flag.ContinueOnError)
	global.SetOutput(a.stderr)
	global.StringVar(&a.socketPath, "socket", a.socketPath, "daemon socket path")
	global.StringVar(&a.vaultPath, "vault", a.vaultPath, "vault file path")
	global.Usage = func() { fmt.Fprint(a.stderr, usage) }

	if err := global.Parse(args); err != nil {
		return ExitError
	}
	rest := global.Args()
	if len(rest) == 0 {
		fmt.Fprint(a.stderr, usage)
		return ExitError
	}

	command, commandArgs := rest[0], rest[1:]

	var runErr error
	switch command {
	case "init":
		runErr = a.cmdInit(commandArgs)
	case "unlock":
		runErr = a.cmdUnlock(commandArgs)
	case "lock":
		runErr = a.cmdLock(commandArgs)
	case "status":
		runErr = a.cmdStatus(commandArgs)
	case "ls", "list":
		runErr = a.cmdList(commandArgs)
	case "add":
		runErr = a.cmdAdd(commandArgs)
	case "get":
		runErr = a.cmdGet(commandArgs)
	case "rm", "remove", "delete":
		runErr = a.cmdRemove(commandArgs)
	case "help", "-h", "--help":
		fmt.Fprint(a.stdout, usage)
		return ExitOK
	default:
		fmt.Fprintf(a.stderr, "openpass: unknown command %q\n\n%s", command, usage)
		return ExitError
	}

	return a.report(runErr)
}

// parseArgs parses flags that may appear before or after positional arguments.
//
// flag.Parse stops at the first non-flag argument, so `add GitHub -user me`
// would otherwise treat "-user me" as two more positionals and silently drop
// them. Resuming the parse after each positional accepts both orders, which is
// what anyone who has used git expects.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// report prints an error and maps it onto an exit code.
func (a *app) report(err error) int {
	if err == nil {
		return ExitOK
	}

	var ambiguous *client.AmbiguousError
	if errors.As(err, &ambiguous) {
		fmt.Fprintf(a.stderr, "openpass: %v:\n", ambiguous)
		for _, e := range ambiguous.Matches {
			fmt.Fprintf(a.stderr, "  %s  %s  %s\n", e.ID[:8], e.Name, e.Username)
		}
		fmt.Fprintf(a.stderr, "be more specific, or use an id\n")
		return ExitAmbiguous
	}

	var notFound *client.NotFoundError
	if errors.As(err, &notFound) {
		fmt.Fprintf(a.stderr, "openpass: %v\n", err)
		return ExitNotFound
	}

	fmt.Fprintf(a.stderr, "openpass: %v\n", err)

	switch {
	case client.IsCode(err, client.CodeVaultLocked):
		return ExitLocked
	case client.IsCode(err, client.CodeNotFound):
		return ExitNotFound
	default:
		return ExitError
	}
}

// connect dials the daemon, starting it if necessary.
func (a *app) connect() (*client.Client, error) {
	return client.DialOrSpawn(a.socketPath, a.vaultPath, client.FindDaemonBinary())
}

// withUnlocked runs fn, and if the vault turns out to be locked, prompts for
// the master password and runs it once more.
//
// Exactly one retry. A loop here would train the user to type their master
// password at any prompt that asks, which is how credential phishing works.
func (a *app) withUnlocked(fn func(*client.Client) error) error {
	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	lockedErr := fn(c)
	if !client.IsCode(lockedErr, client.CodeVaultLocked) {
		return lockedErr
	}

	if err := unlockInteractively(c); err != nil {
		// Report that the vault is locked, not that we could not prompt. A
		// script needs the locked exit code to know it should run `unlock`;
		// masking it with a terminal error loses that.
		if errors.Is(err, errNoTerminal) {
			return lockedErr
		}
		return err
	}
	return fn(c)
}

// connectUnlocked dials the daemon and unlocks it up front.
//
// Commands that have to prompt for something of their own use this instead of
// withUnlocked, so the master password is asked for *before* the command's own
// prompt. Lazily unlocking would ask for the new entry's password first and
// then the master password, which reads like the tool lost track of what it
// was doing.
func (a *app) connectUnlocked() (*client.Client, error) {
	c, err := a.connect()
	if err != nil {
		return nil, err
	}

	status, err := c.Status()
	if err != nil {
		c.Close()
		return nil, err
	}
	if !status.Locked {
		return c, nil
	}

	if err := unlockInteractively(c); err != nil {
		c.Close()
		// With no terminal we cannot ask for the master password, and we will
		// not read it from a pipe. Report it as locked so the exit code tells a
		// script to run `openpass unlock` rather than looking for a bug.
		if errors.Is(err, errNoTerminal) {
			return nil, &client.Error{
				Code:    client.CodeVaultLocked,
				Message: "vault is locked and there is no terminal to unlock it on: run `openpass unlock` first",
			}
		}
		return nil, err
	}
	return c, nil
}

func unlockInteractively(c *client.Client) error {
	password, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer crypto.Zero(password)

	return c.Unlock(password)
}

func (a *app) cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	status, err := c.Status()
	if err != nil {
		return err
	}
	if status.VaultPresent {
		return fmt.Errorf("a vault already exists at %s", a.vaultPath)
	}

	fmt.Fprintf(a.stderr, "Choose a master password. There is no way to recover it:\n")
	password, err := promptNewPassword()
	if err != nil {
		return err
	}
	defer crypto.Zero(password)

	if err := c.Init(password); err != nil {
		return err
	}

	fmt.Fprintf(a.stdout, "Created %s\n", a.vaultPath)
	return nil
}

func (a *app) cmdUnlock(args []string) error {
	fs := flag.NewFlagSet("unlock", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	password, err := promptPassword("Master password: ")
	if err != nil {
		return err
	}
	defer crypto.Zero(password)

	if err := c.Unlock(password); err != nil {
		return err
	}

	status, err := c.Status()
	if err == nil && status.LocksIn != nil {
		fmt.Fprintf(a.stdout, "Unlocked. Locks again after %ds idle.\n", *status.LocksIn)
	} else {
		fmt.Fprintln(a.stdout, "Unlocked.")
	}
	return nil
}

func (a *app) cmdLock(args []string) error {
	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Lock(); err != nil {
		return err
	}
	fmt.Fprintln(a.stdout, "Locked.")
	return nil
}

func (a *app) cmdStatus(args []string) error {
	c, err := a.connect()
	if err != nil {
		return err
	}
	defer c.Close()

	s, err := c.Status()
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "vault\t%s\n", a.vaultPath)
	fmt.Fprintf(tw, "present\t%t\n", s.VaultPresent)
	fmt.Fprintf(tw, "locked\t%t\n", s.Locked)
	if s.EntryCount != nil {
		fmt.Fprintf(tw, "entries\t%d\n", *s.EntryCount)
	}
	if s.LocksIn != nil {
		fmt.Fprintf(tw, "locks in\t%ds\n", *s.LocksIn)
	}
	return tw.Flush()
}

func (a *app) cmdList(args []string) error {
	fs := flag.NewFlagSet("ls", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	tag := fs.String("tag", "", "only entries with this tag")
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	return a.withUnlocked(func(c *client.Client) error {
		entries, err := c.List()
		if err != nil {
			return err
		}

		if *tag != "" {
			entries = filterByTag(entries, *tag)
		}
		sort.Slice(entries, func(i, j int) bool {
			return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
		})

		if len(entries) == 0 {
			fmt.Fprintln(a.stderr, "No entries.")
			return nil
		}

		tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tUSERNAME\tURLS")
		for _, e := range entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
				e.ID[:8], e.Name, e.Username, strings.Join(e.URLs, ", "))
		}
		return tw.Flush()
	})
}

func filterByTag(entries []client.Entry, tag string) []client.Entry {
	var kept []client.Entry
	for _, e := range entries {
		for _, t := range e.Tags {
			if strings.EqualFold(t, tag) {
				kept = append(kept, e)
				break
			}
		}
	}
	return kept
}

func (a *app) cmdAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	username := fs.String("user", "", "username for the entry")
	url := fs.String("url", "", "URL for the entry (repeatable as a comma-separated list)")
	tags := fs.String("tags", "", "comma-separated tags")
	notes := fs.String("notes", "", "freeform notes")
	generate := fs.Bool("gen", false, "generate a random password instead of prompting")
	length := fs.Int("len", 24, "length of the generated password")
	stdin := fs.Bool("stdin", false, "read an existing password from stdin instead of prompting")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: openpass add <name> [flags]")
	}
	name := positional[0]

	if *generate && *stdin {
		return errors.New("-gen and -stdin are mutually exclusive: one generates a password, the other reads one")
	}

	// Unlock before prompting, so the master password is asked for first.
	c, err := a.connectUnlocked()
	if err != nil {
		return err
	}
	defer c.Close()

	// Three ways to supply the password: generate one, read an existing one
	// from a pipe, or type it.
	var password []byte
	switch {
	case *generate:
		password, err = generatePassword(*length)
	case *stdin:
		password, err = readSecretFromStdin()
	default:
		password, err = promptNewSecret("Password for " + name + ": ")
	}
	if err != nil {
		return err
	}
	defer crypto.Zero(password)

	id, err := c.Add(client.AddParams{
		Name:     name,
		Username: *username,
		Password: string(password),
		URLs:     splitList(*url),
		Tags:     splitList(*tags),
		Notes:    *notes,
	})
	if err != nil {
		return err
	}

	fmt.Fprintf(a.stdout, "Added %s (%s)\n", name, id[:8])
	if *generate {
		if err := a.deliverSecret(password, name); err != nil {
			return err
		}
	}
	return nil
}

func (a *app) cmdGet(args []string) error {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	field := fs.String("field", "password", "which field to print: password, username, or url")
	clip := fs.Bool("clip", false, "copy to the clipboard even when piped")
	print := fs.Bool("print", false, "write to stdout even when attached to a terminal")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: openpass get <name|id> [flags]")
	}
	query := positional[0]

	var entry client.Entry
	err = a.withUnlocked(func(c *client.Client) error {
		id, err := c.Resolve(query)
		if err != nil {
			return err
		}
		entry, err = c.Get(id, *field == "password")
		return err
	})
	if err != nil {
		return err
	}

	var value string
	switch *field {
	case "password":
		value = entry.Password
	case "username":
		value = entry.Username
	case "url":
		value = strings.Join(entry.URLs, "\n")
	default:
		return fmt.Errorf("unknown field %q: want password, username, or url", *field)
	}

	// Non-secret fields always print; there is nothing to protect.
	if *field != "password" {
		fmt.Fprintln(a.stdout, value)
		return nil
	}

	switch {
	case *print:
		fmt.Fprintln(a.stdout, value)
		return nil
	case *clip || isTerminal(os.Stdout):
		// Interactive use goes to the clipboard, so a password does not end up
		// in terminal scrollback. Piping gets the raw value, so scripting works.
		return a.deliverSecret([]byte(value), entry.Name)
	default:
		// Piped: raw value, no trailing newline, so `openpass get x | cmd`
		// passes exactly the password.
		fmt.Fprint(a.stdout, value)
		return nil
	}
}

func (a *app) cmdRemove(args []string) error {
	fs := flag.NewFlagSet("rm", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	force := fs.Bool("f", false, "do not ask for confirmation")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: openpass rm <name|id> [-f]")
	}
	query := positional[0]

	return a.withUnlocked(func(c *client.Client) error {
		id, err := c.Resolve(query)
		if err != nil {
			return err
		}

		entry, err := c.Get(id, false)
		if err != nil {
			return err
		}

		// Deletion takes the history with it and the only copy is one
		// generation of .bak, so confirm by default.
		if !*force {
			ok, err := confirm(fmt.Sprintf("Delete %q (%s)?", entry.Name, entry.Username))
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintln(a.stderr, "Cancelled.")
				return nil
			}
		}

		if err := c.Delete(id); err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Deleted %s\n", entry.Name)
		return nil
	})
}

// deliverSecret copies a secret to the clipboard, falling back to printing it
// if no clipboard tool is available.
func (a *app) deliverSecret(secret []byte, label string) error {
	if err := copyToClipboard(secret); err != nil {
		fmt.Fprintf(a.stderr, "could not reach the clipboard (%v), printing instead:\n", err)
		fmt.Fprintln(a.stdout, string(secret))
		return nil
	}
	fmt.Fprintf(a.stderr, "Copied %s to the clipboard.\n", label)
	return nil
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
