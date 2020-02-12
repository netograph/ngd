package cli

import (
	"github.com/spf13/cobra"
)

var Cmd = &cobra.Command{
	Use:          "ngs",
	Short:        "netograph/spur utilities",
	SilenceUsage: true,
}

func init() {
	Cmd.AddCommand(
		domainsCommand(),
	)
}
