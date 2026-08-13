package rules

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
)

// scopeCache builds one reference-resolution scope per directory and reuses
// it, so scanning twenty files in the same module reads that module's .tf
// files once rather than twenty times.
type scopeCache struct {
	repoDir string
	byDir   map[string]*hcl.EvalContext
}

func newScopeCache(repoDir string) *scopeCache {
	return &scopeCache{repoDir: repoDir, byDir: map[string]*hcl.EvalContext{}}
}

// forFile returns the scope for the directory containing path. headContent is
// the content being scanned, which takes precedence over the copy on disk.
//
// With no repoDir configured this returns nil, and every reference stays
// unresolved — the behaviour before scopes existed.
func (c *scopeCache) forFile(path string, headContent []byte) *hcl.EvalContext {
	if c.repoDir == "" {
		return nil
	}

	dir := filepath.Dir(path)
	if cached, ok := c.byDir[dir]; ok {
		return cached
	}

	files := c.readDir(dir)
	if headContent != nil {
		files[path] = headContent
	}
	scope := parser.BuildScope(files)
	c.byDir[dir] = scope
	return scope
}

// readDir loads the .tf files of one directory, non-recursively — Terraform
// scopes locals and variables to a single directory and does not descend.
func (c *scopeCache) readDir(dir string) map[string][]byte {
	out := map[string][]byte{}

	full := filepath.Join(c.repoDir, dir)
	// Refuse to read outside the repository. `dir` comes from a git path so it
	// should already be clean, but a scanner that reads arbitrary files
	// because of a crafted path in someone's PR is not a trade worth taking.
	absRoot, err := filepath.Abs(c.repoDir)
	if err != nil {
		return out
	}
	absDir, err := filepath.Abs(full)
	if err != nil || (absDir != absRoot && !strings.HasPrefix(absDir, absRoot+string(os.PathSeparator))) {
		return out
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		// A directory we can't read (deleted in this PR, permissions) just
		// means no scope for it, not a failed scan.
		return out
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tf") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(absDir, e.Name()))
		if err != nil {
			continue
		}
		out[filepath.Join(dir, e.Name())] = src
	}
	return out
}
