package cli

import (
	"errors"
	"flag"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/chetankar/openpass/internal/client"
)

// cmdMatch shows which entries a page URL resolves to. It is the same call the
// browser extension makes on every navigation, which makes it the fastest way
// to check matching behaviour by hand.
func (a *app) cmdMatch(args []string) error {
	fs := flag.NewFlagSet("match", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	insecure := fs.Bool("insecure", false, "allow matching http:// pages")

	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return errors.New("usage: openpass match <url> [-insecure]")
	}

	return a.withUnlocked(func(c *client.Client) error {
		result, err := c.Match(positional[0], *insecure)
		if err != nil {
			return err
		}

		fmt.Fprintf(a.stdout, "domain: %s\n", result.Domain)
		if len(result.Entries) == 0 {
			fmt.Fprintln(a.stdout, "no entries for this site")
			return nil
		}

		tw := tabwriter.NewWriter(a.stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tUSERNAME\tURLS")
		for _, e := range result.Entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", e.ID[:8], e.Name, e.Username, strings.Join(e.URLs, ", "))
		}
		return tw.Flush()
	})
}
