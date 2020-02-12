package main

import (
	"os"

	"github.com/netograph/ngd/src/cmd/ngd/cli"
)

func main() {
	if err := cli.Cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
