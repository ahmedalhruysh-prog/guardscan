package secret

import (
	"regexp"

	"github.com/ahmedalhruysh-prog/guardscan/internal/finding"
)

// PatternDetector كاشف يعتمد على التعبيرات النمطية
type PatternDetector struct {
	patterns []PatternRule
}

// PatternRule قاعدة كشف
type PatternRule struct {
	ID          string
	Title       string
	Regex       *regexp.Regexp
	Severity    finding.Severity
	Confidence  finding.Confidence
	Remediation string
	References  []string
}

// NewPatternDetector ينشئ كاشفاً جديداً
func NewPatternDetector() *PatternDetector {
	return &PatternDetector{
		patterns: []PatternRule{
			{
				ID:          "SEC-AWS-ACCESS-KEY",
				Title:       "AWS Access Key",
				Regex:       regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Revoke the key and rotate it immediately.",
				References:  []string{"https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html"},
			},
			{
				ID:          "SEC-GITHUB-PAT",
				Title:       "GitHub Personal Access Token",
				Regex:       regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Revoke the token and rotate it.",
				References:  []string{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token"},
			},
			{
				ID:          "SEC-GENERIC-PASSWORD",
				Title:       "Generic Hardcoded Password",
				Regex:       regexp.MustCompile(`(?i)password\s*[:=]\s*['"][^'"]{4,}['"]`),
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceMedium,
				Remediation: "Use environment variables or a secret manager.",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
			},
			{
				ID:          "SEC-PRIVATE-KEY",
				Title:       "Private Key",
				Regex:       regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Remove the key from the repository and regenerate it.",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key"},
			},
		},
	}
}

// Detect يفحص سطراً ويعيد النتائج
func (d *PatternDetector) Detect(line string, lineNum int, filePath string) []finding.Finding {
	var results []finding.Finding
	for _, rule := range d.patterns {
		if rule.Regex.MatchString(line) {
			// 🛡️ تعتيم القيمة (لا نعرض السر كاملاً)
			redacted := "[REDACTED]"
			results = append(results, finding.Finding{
				RuleID:      rule.ID,
				Scanner:     finding.ScannerSecret,
				Title:       rule.Title,
				Description: "A potential secret was detected.",
				Severity:    rule.Severity,
				Confidence:  rule.Confidence,
				File:        filePath,
				Line:        lineNum,
				Evidence:    redacted,
				Remediation: rule.Remediation,
				References:  rule.References,
			})
		}
	}
	return results
}
