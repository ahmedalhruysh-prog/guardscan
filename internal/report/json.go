package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/ahmedalhruysh-prog/guardscan/internal/finding"
)

// Report يمثل التقرير الكامل
type Report struct {
	Tool            string            `json:"tool"`
	Version         string            `json:"version"`
	ScannedPath     string            `json:"scanned_path"`
	GeneratedAt     string            `json:"generated_at"`
	IssueCount      int               `json:"issue_count"`
	SeveritySummary map[string]int    `json:"severity_summary"`
	Issues          []finding.Finding `json:"issues"`
}

// WriteJSON يكتب التقرير بصيغة JSON
func WriteJSON(outputPath, scannedPath string, findings []finding.Finding) error {
	severitySummary := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}

	for _, f := range findings {
		severitySummary[string(f.Severity)]++
	}

	report := Report{
		Tool:            "GuardScan",
		Version:         "0.1.0-dev",
		ScannedPath:     scannedPath,
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		IssueCount:      len(findings),
		SeveritySummary: severitySummary,
		Issues:          findings,
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}
