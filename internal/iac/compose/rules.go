package compose

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
		ID:          "IAC-COMPOSE-001",
		Title:       "Privileged mode enabled",
		Regex:       regexp.MustCompile(`(?i)^\s*privileged:\s*true`),
		Severity:    finding.SeverityCritical,
		Confidence:  finding.ConfidenceHigh,
		Remediation: "Remove 'privileged: true' and grant only necessary capabilities.",
		References:  []string{"https://docs.docker.com/compose/compose-file/#privileged"},
	},
	{
		ID:          "IAC-COMPOSE-002",
		Title:       "Docker socket mounted",
		Regex:       regexp.MustCompile(`(?i)/var/run/docker\.sock`),
		Severity:    finding.SeverityCritical,
		Confidence:  finding.ConfidenceHigh,
		Remediation: "Do not mount the Docker socket; use a dedicated API instead.",
		References:  []string{"https://docs.docker.com/engine/security/security/#docker-daemon-attack-surface"},
	},
	{
		ID:          "IAC-COMPOSE-003",
		Title:       "Host network mode",
		Regex:       regexp.MustCompile(`(?i)^\s*network_mode:\s*host`),
		Severity:    finding.SeverityHigh,
		Confidence:  finding.ConfidenceHigh,
		Remediation: "Use a bridge network instead of host mode.",
		References:  []string{"https://docs.docker.com/compose/compose-file/#network_mode"},
	},
	{
		ID:          "IAC-COMPOSE-004",
		Title:       "Sensitive host volume mounted",
		Regex:       regexp.MustCompile(`(?i)^\s*-\s*/(etc|root|var|usr|boot|sys|proc):`),
		Severity:    finding.SeverityHigh,
		Confidence:  finding.ConfidenceMedium,
		Remediation: "Avoid mounting sensitive host directories; use named volumes.",
		References:  []string{"https://docs.docker.com/compose/compose-file/#volumes"},
	},
}
