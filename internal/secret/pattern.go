package secret

import (
	"regexp"

	"github.com/ahmedalhruysh-prog/guardscan/internal/finding"
)

type PatternDetector struct {
	patterns []PatternRule
}

type PatternRule struct {
	ID          string
	Title       string
	Regex       *regexp.Regexp
	Severity    finding.Severity
	Confidence  finding.Confidence
	Remediation string
	References  []string
}

func NewPatternDetector() *PatternDetector {
	return &PatternDetector{
		patterns: []PatternRule{
			// AWS
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
				ID:          "SEC-AWS-SECRET-KEY",
				Title:       "AWS Secret Access Key",
				Regex:       regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Revoke the key and rotate it.",
				References:  []string{"https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html"},
			},
			// GitHub
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
				ID:          "SEC-GITHUB-OAUTH",
				Title:       "GitHub OAuth Token",
				Regex:       regexp.MustCompile(`gho_[A-Za-z0-9]{36}`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Revoke the token.",
				References:  []string{"https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token"},
			},
			// GitLab
			{
				ID:          "SEC-GITLAB-PAT",
				Title:       "GitLab Personal Access Token",
				Regex:       regexp.MustCompile(`glpat-[A-Za-z0-9\-_]{20}`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Revoke the token.",
				References:  []string{"https://docs.gitlab.com/ee/user/profile/personal_access_tokens.html"},
			},
			// Slack
			{
				ID:          "SEC-SLACK-TOKEN",
				Title:       "Slack Token",
				Regex:       regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Revoke the token.",
				References:  []string{"https://api.slack.com/authentication/token-types"},
			},
			// Google
			{
				ID:          "SEC-GOOGLE-API-KEY",
				Title:       "Google API Key",
				Regex:       regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Restrict or revoke the key.",
				References:  []string{"https://cloud.google.com/docs/authentication/api-keys"},
			},
			// Stripe
			{
				ID:          "SEC-STRIPE-LIVE",
				Title:       "Stripe Live Secret Key",
				Regex:       regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Revoke the key immediately.",
				References:  []string{"https://stripe.com/docs/keys"},
			},
			{
				ID:          "SEC-STRIPE-TEST",
				Title:       "Stripe Test Secret Key",
				Regex:       regexp.MustCompile(`sk_test_[0-9a-zA-Z]{24}`),
				Severity:    finding.SeverityMedium,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Test key exposed. Rotate if necessary.",
				References:  []string{"https://stripe.com/docs/keys"},
			},
			// Private Keys
			{
				ID:          "SEC-PRIVATE-KEY",
				Title:       "Private Key",
				Regex:       regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Remove the key from the repository and regenerate it.",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_cryptographic_key"},
			},
			// JWT
			{
				ID:          "SEC-JWT-TOKEN",
				Title:       "JSON Web Token",
				Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`),
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceMedium,
				Remediation: "Revoke the token and rotate the signing key.",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/JSON_Web_Token"},
			},
			// Generic
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
				ID:          "SEC-GENERIC-API-KEY",
				Title:       "Generic API Key",
				Regex:       regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*['"][^'"]{8,}['"]`),
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceMedium,
				Remediation: "Use environment variables or a secret manager.",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
			},
			{
				ID:          "SEC-CONNECTION-STRING",
				Title:       "Database Connection String",
				Regex:       regexp.MustCompile(`(?i)(mongodb|postgres|mysql|redis)://[^@\s]+@[^/\s]+`),
				Severity:    finding.SeverityHigh,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Move connection strings to environment variables.",
				References:  []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
			},
			// Cloud
			{
				ID:          "SEC-AZURE-CONN-STR",
				Title:       "Azure Connection String",
				Regex:       regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net`),
				Severity:    finding.SeverityCritical,
				Confidence:  finding.ConfidenceHigh,
				Remediation: "Rotate the key.",
				References:  []string{"https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage"},
			},
		},
	}
}

func (d *PatternDetector) Detect(line string, lineNum int, filePath string) []finding.Finding {
	var results []finding.Finding
	for _, rule := range d.patterns {
		if rule.Regex.MatchString(line) {
			results = append(results, finding.Finding{
				RuleID:      rule.ID,
				Scanner:     finding.ScannerSecret,
				Title:       rule.Title,
				Description: "A potential secret was detected.",
				Severity:    rule.Severity,
				Confidence:  rule.Confidence,
				File:        filePath,
				Line:        lineNum,
				Evidence:    "[REDACTED]",
				Remediation: rule.Remediation,
				References:  rule.References,
			})
		}
	}
	return results
}
