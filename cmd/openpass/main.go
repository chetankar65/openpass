package main

import (
	"os"

	"github.com/chetankar/openpass/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
