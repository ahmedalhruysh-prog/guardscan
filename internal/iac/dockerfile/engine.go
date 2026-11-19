package dockerfile

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
	return "iac-dockerfile"
}

func (e *Engine) CanScan(file core.FileInfo) bool {
	base := strings.ToLower(filepath.Base(file.Path))
	return base == "dockerfile" || strings.HasSuffix(base, ".dockerfile")
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
	hasHealthcheck := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// فحص خاص لقاعدة HEALTHCHECK (لأنها تفحص غياب الأمر)
		if strings.HasPrefix(strings.ToUpper(line), "HEALTHCHECK") {
			hasHealthcheck = true
		}

		for _, rule := range Rules {
			if rule.ID == "IAC-DOCKER-004" {
				continue // نتعامل معها بعد الحلقة
			}
			if rule.Regex.MatchString(line) {
				results = append(results, finding.Finding{
					RuleID:      rule.ID,
					Scanner:     finding.ScannerIaC,
					Title:       rule.Title,
					Description: "Insecure Dockerfile configuration detected.",
					Severity:    rule.Severity,
					Confidence:  rule.Confidence,
					File:        file.RelPath,
					Line:        lineNum,
					Evidence:    line,
					Remediation: rule.Remediation,
					References:  rule.References,
				})
			}
		}
	}

	// فحص HEALTHCHECK بعد قراءة الملف كاملاً
	if !hasHealthcheck {
		for _, rule := range Rules {
			if rule.ID == "IAC-DOCKER-004" {
				results = append(results, finding.Finding{
					RuleID:      rule.ID,
					Scanner:     finding.ScannerIaC,
					Title:       rule.Title,
					Description: "No HEALTHCHECK instruction found.",
					Severity:    rule.Severity,
					Confidence:  rule.Confidence,
					File:        file.RelPath,
					Line:        1,
					Evidence:    "No HEALTHCHECK in file",
					Remediation: rule.Remediation,
					References:  rule.References,
				})
			}
		}
	}

	return results, scanner.Err()
}
