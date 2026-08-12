// Package diff retrieves the .tf files changed in a PR and, where needed,
// their pre-change ("base") content — using a local git checkout. The
// scanner never needs cloud credentials or a terraform state file.
package diff

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	if err := validateRefs(repoDir, baseRef, headRef); err != nil {
		return nil, err
	}

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
		base, _ := showFile(repoDir, baseRef, p) // nil is fine: new file
		files = append(files, ChangedFile{Path: p, HeadContent: head, BaseContent: base})
	}
	return files, nil
}

// ChangedTerragruntFiles returns every terragrunt.hcl file that differs
// between baseRef and headRef — Terragrunt's own config format (`inputs`,
// `remote_state`, ...), not a .tf resource file, so it needs its own git
// pathspec rather than being picked up by ChangedTerraformFiles' *.tf glob.
func ChangedTerragruntFiles(repoDir, baseRef, headRef string) ([]ChangedFile, error) {
	if err := validateRefs(repoDir, baseRef, headRef); err != nil {
		return nil, err
	}

	paths, err := changedPathsMatching(repoDir, baseRef, headRef, "**/terragrunt.hcl")
	if err != nil {
		return nil, err
	}

	var files []ChangedFile
	for _, p := range paths {
		head, err := showFile(repoDir, headRef, p)
		if err != nil {
			continue // deleted at head; nothing to scan
		}
		files = append(files, ChangedFile{Path: p, HeadContent: head})
	}
	return files, nil
}

// AllTerragruntFiles walks repoDir for every terragrunt.hcl file — the
// terragrunt.hcl equivalent of AllTerraformFiles, for the scheduled drift
// audit.
func AllTerragruntFiles(repoDir string) ([]ChangedFile, error) {
	var files []ChangedFile
	err := filepath.WalkDir(repoDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != "terragrunt.hcl" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			rel = path
		}
		files = append(files, ChangedFile{Path: rel, HeadContent: content})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s for terragrunt.hcl files: %w", repoDir, err)
	}
	return files, nil
}

// AllTerraformFiles walks repoDir for every *.tf file and returns it as a
// ChangedFile with BaseContent set equal to HeadContent — for a scheduled
// drift audit of code that's already merged, not a PR diff. Setting Base
// equal to Head means diff-based rules (ForceNew) correctly find nothing
// "changed" (there's no PR to diff against), while rules that only look at
// current content (unknown attributes, tutorial patterns, missing
// prevent_destroy) still run at full strength — this is what catches
// Terraform that was clean when it merged but is no longer clean because
// the scanner's own rule/schema coverage grew since then.
func AllTerraformFiles(repoDir string) ([]ChangedFile, error) {
	var files []ChangedFile
	err := filepath.WalkDir(repoDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == ".terraform" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".tf") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", path, err)
		}
		rel, err := filepath.Rel(repoDir, path)
		if err != nil {
			rel = path
		}
		files = append(files, ChangedFile{Path: rel, HeadContent: content, BaseContent: content})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking %s for .tf files: %w", repoDir, err)
	}
	return files, nil
}

// validateRefs checks that both refs are reachable and provides a
// human-readable hint when a common failure mode is detected (shallow
// clone, missing fetch of the base branch).
func validateRefs(repoDir, baseRef, headRef string) error {
	for _, ref := range []string{baseRef, headRef} {
		cmd := exec.Command("git", "-C", repoDir, "rev-parse", "--verify", ref)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			hint := buildRefHint(repoDir, ref)
			return fmt.Errorf(
				"git ref %q not found — cannot compute the PR diff.\n%s\nOriginal error: %s",
				ref, hint, strings.TrimSpace(stderr.String()),
			)
		}
	}
	return nil
}

func buildRefHint(repoDir, ref string) string {
	// Detect shallow clone: .git/shallow exists and is non-empty.
	shallowCmd := exec.Command("git", "-C", repoDir, "rev-parse", "--is-shallow-repository")
	if out, err := shallowCmd.Output(); err == nil && strings.TrimSpace(string(out)) == "true" {
		return "hint: the repository is a shallow clone.\n" +
			"      Add `fetch-depth: 0` to your actions/checkout step so the base branch history is available:\n\n" +
			"      - uses: actions/checkout@v4\n" +
			"        with:\n" +
			"          fetch-depth: 0"
	}
	// Detect that ref looks like a remote branch that wasn't fetched.
	if strings.HasPrefix(ref, "origin/") {
		branch := strings.TrimPrefix(ref, "origin/")
		return fmt.Sprintf(
			"hint: the remote ref %q was not fetched.\n"+
				"      Make sure your workflow fetches the base branch:\n\n"+
				"      - uses: actions/checkout@v4\n"+
				"        with:\n"+
				"          fetch-depth: 0\n\n"+
				"      Or fetch it explicitly:\n\n"+
				"      - run: git fetch origin %s", ref, branch,
		)
	}
	return "hint: verify that both --base-ref and --head-ref are valid git refs in the repository."
}

func changedPaths(repoDir, baseRef, headRef string) ([]string, error) {
	return changedPathsMatching(repoDir, baseRef, headRef, "*.tf")
}

func changedPathsMatching(repoDir, baseRef, headRef, pathspec string) ([]string, error) {
	cmd := exec.Command("git", "-C", repoDir, "diff", "--name-only", baseRef+"..."+headRef, "--", pathspec)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git diff failed: %w\n%s", err, strings.TrimSpace(stderr.String()))
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
		return nil, fmt.Errorf("git show %s:%s: %w", ref, path, err)
	}
	return out.Bytes(), nil
}
