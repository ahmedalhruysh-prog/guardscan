package compose

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/ahmedalhruysh-prog/guardscan/internal/core"
	"github.com/ahmedalhruysh-prog/guardscan/internal/finding"
)

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Name() string {
	return "iac-compose"
}

func (e *Engine) CanScan(file core.FileInfo) bool {
	base := strings.ToLower(filepath.Base(file.Path))
	return base == "docker-compose.yml" || base == "docker-compose.yaml" ||
		base == "compose.yml" || base == "compose.yaml"
}

func (e *Engine) Scan(file core.FileInfo) ([]finding.Finding, error) {
	var results []finding.Finding

	f, err := os.Open(file.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}

		for _, rule := range Rules {
			if rule.Regex.MatchString(line) {
				results = append(results, finding.Finding{
					RuleID:      rule.ID,
					Scanner:     finding.ScannerIaC,
					Title:       rule.Title,
					Description: "Insecure Docker Compose configuration detected.",
					Severity:    rule.Severity,
					Confidence:  rule.Confidence,
					File:        file.RelPath,
					Line:        lineNum,
					Evidence:    strings.TrimSpace(line),
					Remediation: rule.Remediation,
					References:  rule.References,
				})
			}
		}
	}

	return results, scanner.Err()
}
