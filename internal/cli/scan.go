package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	scanners []string
	format   string
)

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project for secrets and IaC misconfigurations",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		targetPath := args[0]
		fmt.Printf("🔍 Scanning: %s\n", targetPath)
		fmt.Printf("   Scanners: %v\n", scanners)
		fmt.Printf("   Format:   %s\n", format)
		fmt.Println("⏳ Engine not implemented yet (coming in Step 3.3).")
		return nil
	},
}

func init() {
	scanCmd.Flags().StringSliceVar(&scanners, "scanners", []string{"secret", "iac"}, "Scanners to run (secret, iac)")
	scanCmd.Flags().StringVar(&format, "format", "cli", "Output format (cli, json, sarif)")
	rootCmd.AddCommand(scanCmd)
}
