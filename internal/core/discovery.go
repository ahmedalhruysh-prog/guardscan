package core

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ahmedalhruysh-prog/guardscan/internal/security"
)

// FileInfo يمثل ملفاً تم اكتشافه
type FileInfo struct {
	Path      string
	RelPath   string
	Size      int64
	Extension string
}

// DiscoveryEngine محرك اكتشاف الملفات
type DiscoveryEngine struct {
	RootPath string
	Ignores  []string
}

// NewDiscoveryEngine ينشئ محركاً جديداً
func NewDiscoveryEngine(rootPath string) *DiscoveryEngine {
	return &DiscoveryEngine{
		RootPath: rootPath,
		Ignores: []string{
			".git", "node_modules", "venv", "__pycache__",
			"dist", "build", ".idea", ".vscode",
		},
	}
}

// shouldIgnore يتحقق مما إذا كان المسار يجب تجاهله
func (d *DiscoveryEngine) shouldIgnore(path string) bool {
	for _, ignore := range d.Ignores {
		if strings.Contains(path, ignore) {
			return true
		}
	}
	return false
}

// Discover يكتشف جميع الملفات في المسار المحدد
func (d *DiscoveryEngine) Discover() ([]FileInfo, error) {
	// التحقق من المسار (Path Traversal Protection)
	absPath, err := security.ValidatePath(d.RootPath, d.RootPath)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	var files []FileInfo

	err = filepath.Walk(absPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // تخطي الملفات التي لا يمكن الوصول إليها
		}

		// تخطي المجلدات المحظورة
		if d.shouldIgnore(path) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// تخطي المجلدات نفسها
		if info.IsDir() {
			return nil
		}

		// تخطي الملفات الثنائية والصور
		ext := strings.ToLower(filepath.Ext(path))
		skipExts := []string{".png", ".jpg", ".jpeg", ".gif", ".exe", ".dll", ".pyc", ".zip", ".tar", ".gz"}
		for _, skip := range skipExts {
			if ext == skip {
				return nil
			}
		}

		relPath, err := filepath.Rel(absPath, path)
		if err != nil {
			relPath = filepath.Base(path) // احتياطي
		}

		files = append(files, FileInfo{
			Path:      path,
			RelPath:   relPath,
			Size:      info.Size(),
			Extension: ext,
		})

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return files, nil
}
