// Command keyforge is the key lifecycle command line. It talks to a keyforge
// control plane over HTTP; see package cli.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/plexusone/keyforge/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := cli.NewRootCommand(cli.Options{}).ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		stop()
		os.Exit(1)
	}
}
