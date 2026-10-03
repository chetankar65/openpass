package cli

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/term"

	"github.com/chetankar/openpass/internal/crypto"
)

// errNoTerminal means we cannot prompt because stdin is not a terminal.
//
// Callers wrap this with what they were asking for — "the master password" and
// "a password for GitHub" need different advice, and conflating them sends the
// user looking in the wrong place.
var errNoTerminal = errors.New("stdin is not a terminal")

// promptPassword reads a password without echoing it.
//
// term.ReadPassword returns a []byte, which is the whole reason to use it over
// a scanner: a password read into a string could never be zeroed. Passwords are
// never accepted as flags — those land in shell history and in ps output.
func promptPassword(prompt string) ([]byte, error) {
	if !isTerminal(os.Stdin) {
		return nil, errNoTerminal
	}

	fmt.Fprint(os.Stderr, prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, fmt.Errorf("failed to read the password: %w", err)
	}
	if len(password) == 0 {
		return nil, errors.New("the password was empty")
	}
	return password, nil
}

// promptNewPassword reads a password twice and checks the two match, so a typo
// cannot lock you out of a vault you just created.
func promptNewPassword() ([]byte, error) {
	first, err := promptPassword("Master password: ")
	if err != nil {
		return nil, err
	}

	second, err := promptPassword("Confirm: ")
	if err != nil {
		crypto.Zero(first)
		return nil, err
	}
	defer crypto.Zero(second)

	if !bytes.Equal(first, second) {
		crypto.Zero(first)
		return nil, errors.New("the passwords did not match")
	}
	return first, nil
}

// promptNewSecret reads an entry password. Unlike the master password a typo
// here is recoverable with `openpass add` again, so it is only asked once.
func promptNewSecret(prompt string) ([]byte, error) {
	password, err := promptPassword(prompt)
	if errors.Is(err, errNoTerminal) {
		return nil, errors.New("no terminal to prompt on: pass -stdin to read the password from a pipe, or -gen to generate one")
	}
	return password, err
}

// readSecretFromStdin reads a secret piped into the process, for importing a
// password that already exists somewhere else.
//
// There is deliberately no -password flag: a flag value lands in shell history
// and is visible in ps output to every process on the machine. A pipe is the
// only way to hand a secret to a program without leaking it that way.
//
// Exactly one trailing newline is stripped, because `echo secret |` adds one.
// Nothing else is trimmed — a password may legitimately begin or end with a
// space, and silently eating it would store something the user did not type.
func readSecretFromStdin() ([]byte, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("failed to read the password from stdin: %w", err)
	}

	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))

	if len(data) == 0 {
		return nil, errors.New("the password read from stdin was empty")
	}
	return data, nil
}

// confirm asks a yes/no question. Anything other than an explicit yes is no.
func confirm(question string) (bool, error) {
	if !isTerminal(os.Stdin) {
		return false, errors.New("a terminal is required to confirm; pass -f to skip")
	}

	fmt.Fprintf(os.Stderr, "%s [y/N] ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false, err
	}

	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes", nil
}

func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// copyToClipboard puts a secret on the system clipboard.
//
// This shells out rather than taking a cgo clipboard dependency. The secret
// goes in over stdin, never as an argument, so it does not appear in ps.
func copyToClipboard(secret []byte) error {
	var cmd *exec.Cmd
	switch {
	case commandExists("pbcopy"):
		cmd = exec.Command("pbcopy")
	case commandExists("wl-copy"):
		cmd = exec.Command("wl-copy")
	case commandExists("xclip"):
		cmd = exec.Command("xclip", "-selection", "clipboard")
	default:
		return errors.New("no clipboard tool found (pbcopy, wl-copy or xclip)")
	}

	cmd.Stdin = bytes.NewReader(secret)
	return cmd.Run()
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// passwordAlphabet excludes characters that are easy to misread when a
// password has to be typed or read aloud: O/0, l/1/I.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+"

// generatePassword returns a random password of the given length.
//
// Uses rejection-free selection via crypto/rand.Int, which avoids the modulo
// bias you get from reading a byte and taking it mod len(alphabet).
func generatePassword(length int) ([]byte, error) {
	if length < 8 {
		return nil, fmt.Errorf("a generated password must be at least 8 characters, got %d", length)
	}

	out := make([]byte, length)
	max := big.NewInt(int64(len(passwordAlphabet)))
	for i := range out {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return nil, fmt.Errorf("failed to generate a password: %w", err)
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return out, nil
}
