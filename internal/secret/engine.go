package secret

import (
	"bufio"
	"os"
	"strings"

	"github.com/ahmedalhruysh-prog/guardscan/internal/core"
	"github.com/ahmedalhruysh-prog/guardscan/internal/finding"
)

// SecretEngine محرك فحص الأسرار
type SecretEngine struct {
	detector *PatternDetector
}

// NewSecretEngine ينشئ محركاً جديداً
func NewSecretEngine() *SecretEngine {
	return &SecretEngine{
		detector: NewPatternDetector(),
	}
}

// Name اسم المحرك
func (e *SecretEngine) Name() string {
	return "secret"
}

// Scan يفحص ملفاً ويعيد النتائج
func (e *SecretEngine) Scan(file core.FileInfo) ([]finding.Finding, error) {
	var results []finding.Finding

	// تخطي الملفات الكبيرة جداً (> 5MB)
	if file.Size > 5*1024*1024 {
		return nil, nil
	}

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

		// تخطي الأسطر الفارغة
		if strings.TrimSpace(line) == "" {
			continue
		}

		// 1. الكشف بالأنماط
		results = append(results, e.detector.Detect(line, lineNum, file.RelPath)...)

		// 2. الكشف بالعشوائية (للكلمات المفتاحية المشبوهة)
		if strings.Contains(strings.ToLower(line), "key") || strings.Contains(strings.ToLower(line), "secret") {
			// استخراج القيمة بعد علامة =
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				value := strings.TrimSpace(parts[1])
				value = strings.Trim(value, `"'`)
				if IsHighEntropy(value, 4.5) {
					results = append(results, finding.Finding{
						RuleID:      "SEC-HIGH-ENTROPY",
						Scanner:     finding.ScannerSecret,
						Title:       "High Entropy String",
						Description: "A high-entropy string was detected near a secret-related keyword.",
						Severity:    finding.SeverityMedium,
						Confidence:  finding.ConfidenceMedium,
						File:        file.RelPath,
						Line:        lineNum,
						Evidence:    "[high-entropy string]",
						Remediation: "Verify if this is a real secret and remove it.",
						References:  []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
					})
				}
			}
		}
	}

	return results, scanner.Err()
}
