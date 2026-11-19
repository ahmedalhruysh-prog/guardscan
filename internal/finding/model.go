package finding

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

type Confidence string

const (
	ConfidenceHigh    Confidence = "HIGH"
	ConfidenceMedium  Confidence = "MEDIUM"
	ConfidenceLow     Confidence = "LOW"
	ConfidenceUnknown Confidence = "UNKNOWN"
)

type ScannerType string

const (
	ScannerSecret ScannerType = "SECRET"
	ScannerIaC    ScannerType = "IAC"
)

type Finding struct {
	ID          string      `json:"id"`
	RuleID      string      `json:"rule_id"`
	Scanner     ScannerType `json:"scanner"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Severity    Severity    `json:"severity"`
	Confidence  Confidence  `json:"confidence"`

	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`

	Evidence    string   `json:"evidence"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`

	RuleVersion string    `json:"rule_version"`
	DetectedAt  time.Time `json:"detected_at"`

	Suppressed        bool   `json:"suppressed"`
	SuppressionReason string `json:"suppression_reason,omitempty"`
}
