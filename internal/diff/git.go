// Package diff retrieves the .tf files changed in a PR and, where needed,
// their pre-change ("base") content — using a local git checkout. The
// scanner never needs cloud credentials or a terraform state file.
package diff

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// ChangedFile is a .tf file modified between base and head, with both
// revisions' contents (BaseContent is nil if the file is new).
type ChangedFile struct {
	Path        string
	HeadContent []byte
	BaseContent []byte // nil when the file didn't exist at base
}

// ChangedTerraformFiles returns every *.tf file that differs between
// baseRef and headRef in the git repo at repoDir.
func ChangedTerraformFiles(repoDir, baseRef, headRef string) ([]ChangedFile, error) {
	paths, err := changedPaths(repoDir, baseRef, headRef)
	if err != nil {
		return nil, err
	}

	var files []ChangedFile
	for _, p := range paths {
		if !strings.HasSuffix(p, ".tf") {
			continue
		}
		head, err := showFile(repoDir, headRef, p)
		if err != nil {
			// File was deleted at head; nothing to scan.
			continue
		}
		base, _ := showFile(repoDir, baseRef, p) // ok to be nil: new file
		files = append(files, ChangedFile{Path: p, HeadContent: head, BaseContent: base})
	}
	return files, nil
}

func changedPaths(repoDir, baseRef, headRef string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoDir, "diff", "--name-only", baseRef+"..."+headRef, "--", "*.tf")
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff failed: %w: %s", err, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var paths []string
	for _, l := range lines {
		if l != "" {
			paths = append(paths, l)
		}
	}
	return paths, nil
}

func showFile(repoDir, ref, path string) ([]byte, error) {
	cmd := exec.Command("git", "-C", repoDir, "show", ref+":"+path)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git show %s:%s failed: %w: %s", ref, path, err, stderr.String())
	}
	return out.Bytes(), nil
}
