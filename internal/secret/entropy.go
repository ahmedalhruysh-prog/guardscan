package secret

import (
	"math"
)

// ShannonEntropy يحسب عشوائية النص
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, r := range s {
		freq[r]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// IsHighEntropy يتحقق مما إذا كان النص عالي العشوائية
// النصوص العشوائية (Base64، Hex) تكون عادة > 4.0
func IsHighEntropy(s string, threshold float64) bool {
	// نتجاهل النصوص القصيرة جداً
	if len(s) < 16 {
		return false
	}
	return ShannonEntropy(s) >= threshold
}
