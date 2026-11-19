package dockerfile

import (
	"regexp"

	"github.com/ahmedalhruysh-prog/guardscan/internal/finding"
)

type Rule struct {
	ID          string
	Title       string
	Regex       *regexp.Regexp
	Severity    finding.Severity
	Confidence  finding.Confidence
	Remediation string
	References  []string
}

var Rules = []Rule{
	{
		ID:          "IAC-DOCKER-001",
		Title:       "Container runs as root",
		Regex:       regexp.MustCompile(`(?i)^USER\s+root`),
		Severity:    finding.SeverityHigh,
		Confidence:  finding.ConfidenceHigh,
		Remediation: "Create a non-root user and use the USER instruction.",
		References:  []string{"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user"},
	},
	{
		ID:          "IAC-DOCKER-002",
		Title:       "Base image uses 'latest' tag or no tag",
		Regex:       regexp.MustCompile(`(?i)^FROM\s+([^:]+|.*:latest)$`),
		Severity:    finding.SeverityMedium,
		Confidence:  finding.ConfidenceMedium,
		Remediation: "Pin the base image to a specific version or digest.",
		References:  []string{"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#use-multi-stage-builds"},
	},
	{
		ID:          "IAC-DOCKER-003",
		Title:       "ADD used instead of COPY",
		Regex:       regexp.MustCompile(`(?i)^ADD\s+`),
		Severity:    finding.SeverityLow,
		Confidence:  finding.ConfidenceLow,
		Remediation: "Use COPY instead of ADD for local files.",
		References:  []string{"https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#add-or-copy"},
	},
	{
		ID:          "IAC-DOCKER-004",
		Title:       "No HEALTHCHECK instruction",
		Regex:       regexp.MustCompile(`(?i)^HEALTHCHECK`),
		Severity:    finding.SeverityLow,
		Confidence:  finding.ConfidenceMedium,
		Remediation: "Add a HEALTHCHECK instruction to monitor container health.",
		References:  []string{"https://docs.docker.com/engine/reference/builder/#healthcheck"},
	},
}
