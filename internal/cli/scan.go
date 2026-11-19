package cli

import (
	"fmt"

	"github.com/ahmedalhruysh-prog/guardscan/internal/core"
	"github.com/ahmedalhruysh-prog/guardscan/internal/iac/compose"
	"github.com/ahmedalhruysh-prog/guardscan/internal/iac/dockerfile"
	"github.com/ahmedalhruysh-prog/guardscan/internal/secret"
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

		discovery := core.NewDiscoveryEngine(targetPath)
		files, err := discovery.Discover()
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}

		fmt.Printf("\n📁 Discovered %d files\n", len(files))

		// محرك الأسرار
		if contains(scanners, "secret") {
			fmt.Println("\n🔐 Running Secret Engine...")
			engine := secret.NewSecretEngine()
			totalFindings := 0
			for _, f := range files {
				findings, err := engine.Scan(f)
				if err != nil {
					fmt.Printf("   ⚠️  Error scanning %s: %v\n", f.RelPath, err)
					continue
				}
				for _, finding := range findings {
					totalFindings++
					fmt.Printf("   🚨 [%s] %s at %s:%d\n", finding.Severity, finding.Title, finding.File, finding.Line)
				}
			}
			fmt.Printf("\n✅ Secret Engine found %d issues\n", totalFindings)
		}

		// محرك IaC
		if contains(scanners, "iac") {
			fmt.Println("\n🏗️  Running IaC Engine...")

			// Dockerfile
			dockerEngine := dockerfile.NewEngine()
			composeEngine := compose.NewEngine()
			totalFindings := 0

			for _, f := range files {
				// Dockerfile
				if dockerEngine.CanScan(f) {
					findings, err := dockerEngine.Scan(f)
					if err != nil {
						fmt.Printf("   ⚠️  Error scanning %s: %v\n", f.RelPath, err)
					} else {
						for _, finding := range findings {
							totalFindings++
							fmt.Printf("   🚨 [%s] %s at %s:%d\n", finding.Severity, finding.Title, finding.File, finding.Line)
						}
					}
				}

				// Docker Compose
				if composeEngine.CanScan(f) {
					findings, err := composeEngine.Scan(f)
					if err != nil {
						fmt.Printf("   ⚠️  Error scanning %s: %v\n", f.RelPath, err)
					} else {
						for _, finding := range findings {
							totalFindings++
							fmt.Printf("   🚨 [%s] %s at %s:%d\n", finding.Severity, finding.Title, finding.File, finding.Line)
						}
					}
				}
			}
			fmt.Printf("\n✅ IaC Engine found %d issues\n", totalFindings)
		}

		return nil
	},
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func init() {
	scanCmd.Flags().StringSliceVar(&scanners, "scanners", []string{"secret", "iac"}, "Scanners to run (secret, iac)")
	scanCmd.Flags().StringVar(&format, "format", "cli", "Output format (cli, json, sarif)")
	rootCmd.AddCommand(scanCmd)
}
