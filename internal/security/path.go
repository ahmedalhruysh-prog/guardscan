package security

import (
	"fmt"
	"path/filepath"
	"strings"
)

type PathTraversalError struct {
	Target string
}

func (e *PathTraversalError) Error() string {
	return fmt.Sprintf("path traversal detected: %s", e.Target)
}

func ValidatePath(root, target string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("failed to resolve root: %w", err)
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("failed to resolve target: %w", err)
	}
	rootWithSep := absRoot + string(filepath.Separator)
	if absTarget != absRoot && !strings.HasPrefix(absTarget, rootWithSep) {
		return "", &PathTraversalError{Target: target}
	}
	return absTarget, nil
}
