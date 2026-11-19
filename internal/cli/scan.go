package cli

import (
	"fmt"

	"github.com/ahmedalhruysh-prog/guardscan/internal/core"
	"github.com/ahmedalhruysh-prog/guardscan/internal/finding"
	"github.com/ahmedalhruysh-prog/guardscan/internal/iac/compose"
	"github.com/ahmedalhruysh-prog/guardscan/internal/iac/dockerfile"
	"github.com/ahmedalhruysh-prog/guardscan/internal/report"
	"github.com/ahmedalhruysh-prog/guardscan/internal/secret"
	"github.com/spf13/cobra"
)

var (
	scanners   []string
	format     string
	outputPath string
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

		var allFindings []finding.Finding

		// محرك الأسرار
		if contains(scanners, "secret") {
			fmt.Println("\n🔐 Running Secret Engine...")
			engine := secret.NewSecretEngine()
			for _, f := range files {
				findings, err := engine.Scan(f)
				if err != nil {
					fmt.Printf("   ⚠️  Error scanning %s: %v\n", f.RelPath, err)
					continue
				}
				allFindings = append(allFindings, findings...)
			}
		}

		// محرك IaC
		if contains(scanners, "iac") {
			fmt.Println("\n🏗️  Running IaC Engine...")
			dockerEngine := dockerfile.NewEngine()
			composeEngine := compose.NewEngine()

			for _, f := range files {
				if dockerEngine.CanScan(f) {
					findings, err := dockerEngine.Scan(f)
					if err != nil {
						fmt.Printf("   ⚠️  Error scanning %s: %v\n", f.RelPath, err)
					} else {
						allFindings = append(allFindings, findings...)
					}
				}
				if composeEngine.CanScan(f) {
					findings, err := composeEngine.Scan(f)
					if err != nil {
						fmt.Printf("   ⚠️  Error scanning %s: %v\n", f.RelPath, err)
					} else {
						allFindings = append(allFindings, findings...)
					}
				}
			}
		}

		// عرض النتائج
		if format == "json" {
			jsonPath := outputPath
			if jsonPath == "" {
				jsonPath = "guardscan-report.json"
			}
			if err := report.WriteJSON(jsonPath, targetPath, allFindings); err != nil {
				return fmt.Errorf("failed to write JSON report: %w", err)
			}
			fmt.Printf("\n✅ Report written to %s (%d issues)\n", jsonPath, len(allFindings))
		} else {
			// عرض في CLI
			if len(allFindings) == 0 {
				fmt.Println("\n✅ No issues found.")
			} else {
				fmt.Printf("\n🚨 Found %d issues:\n", len(allFindings))
				for _, f := range allFindings {
					fmt.Printf("   [%s] %s at %s:%d\n", f.Severity, f.Title, f.File, f.Line)
				}
			}
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
	scanCmd.Flags().StringVar(&format, "format", "cli", "Output format (cli, json)")
	scanCmd.Flags().StringVar(&outputPath, "output", "", "Output file path (for json format)")
	rootCmd.AddCommand(scanCmd)
}
