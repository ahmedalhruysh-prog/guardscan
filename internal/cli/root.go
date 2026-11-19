package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	Version   = "0.1.0-dev"
	BuildDate = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "guardscan",
	Short: "GuardScan — Secrets & Infrastructure Security Scanner",
	Long: `GuardScan is a standalone, security-first scanner that detects:
  - Exposed secrets (API keys, passwords, private keys).
  - Insecure Infrastructure-as-Code configurations (Docker, K8s, Terraform).`,
	Version: Version,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("GuardScan v%s (built: %s)\n", Version, BuildDate)
		},
	})
}
