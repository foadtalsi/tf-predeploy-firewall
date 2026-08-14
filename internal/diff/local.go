package diff

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Local (non-PR) change sources: the git index, for a pre-commit hook, and
// the working tree, for a developer asking "what would the firewall say?"
// before anything is committed or pushed.
//
// These exist because the PR flow's precondition — two commits to diff — is
// exactly what a local user doesn't have yet. Telling them to commit first
// so the scanner can look is backwards; the entire value of running locally
// is hearing about the hardcoded password *before* it enters history, where
// removing it stops being an edit and becomes a rotation.

// StagedTerraformFiles returns every .tf file with staged changes, staged
// content as head, HEAD's version as base. This is the pre-commit view: what
// the commit would contain, compared against what the branch last said.
func StagedTerraformFiles(repoDir string) ([]ChangedFile, error) {
	return stagedFiles(repoDir, "*.tf")
}

// StagedTerragruntFiles is StagedTerraformFiles for terragrunt.hcl.
func StagedTerragruntFiles(repoDir string) ([]ChangedFile, error) {
	return stagedFiles(repoDir, "**/terragrunt.hcl")
}

func stagedFiles(repoDir, pathspec string) ([]ChangedFile, error) {
	paths, err := gitLines(repoDir, "diff", "--cached", "--name-only", "--", pathspec)
	if err != nil {
		return nil, fmt.Errorf("listing staged files: %w", err)
	}

	var files []ChangedFile
	for _, p := range paths {
		// ":path" is the index blob — the content the commit would actually
		// contain, which can differ from the worktree if the user staged
		// selectively (git add -p). Scanning the worktree instead would pass
		// judgment on lines that aren't in the commit.
		head, err := showFile(repoDir, "", p)
		if err != nil {
			continue // staged deletion; nothing to scan
		}
		// On the very first commit HEAD doesn't exist; every file is new.
		base, _ := showFile(repoDir, "HEAD", p)
		files = append(files, ChangedFile{Path: p, HeadContent: head, BaseContent: base})
	}
	return files, nil
}

// UncommittedTerraformFiles returns every .tf file that differs between the
// working tree and HEAD — staged, unstaged, and untracked alike — with the
// on-disk content as head and HEAD's version as base.
func UncommittedTerraformFiles(repoDir string) ([]ChangedFile, error) {
	return uncommittedFiles(repoDir, "*.tf")
}

// UncommittedTerragruntFiles is UncommittedTerraformFiles for terragrunt.hcl.
func UncommittedTerragruntFiles(repoDir string) ([]ChangedFile, error) {
	return uncommittedFiles(repoDir, "**/terragrunt.hcl")
}

func uncommittedFiles(repoDir, pathspec string) ([]ChangedFile, error) {
	seen := map[string]bool{}
	var paths []string

	// Tracked changes, staged or not. Skipped silently when HEAD doesn't
	// exist (empty repository) — the untracked listing below is then the
	// whole answer.
	if tracked, err := gitLines(repoDir, "diff", "--name-only", "HEAD", "--", pathspec); err == nil {
		for _, p := range tracked {
			if !seen[p] {
				seen[p] = true
				paths = append(paths, p)
			}
		}
	}

	// Untracked files are the most local changes of all — a brand-new
	// main.tf that was never `git add`ed is precisely the file a local scan
	// is asked about. `git diff` never lists them, so they need their own
	// listing, gitignore respected.
	untracked, err := gitLines(repoDir, "ls-files", "--others", "--exclude-standard", "--", pathspec)
	if err != nil {
		return nil, fmt.Errorf("listing untracked files: %w", err)
	}
	for _, p := range untracked {
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	var files []ChangedFile
	for _, p := range paths {
		head, err := os.ReadFile(filepath.Join(repoDir, p))
		if err != nil {
			continue // deleted in the worktree; nothing to scan
		}
		base, _ := showFile(repoDir, "HEAD", p) // nil for new files
		files = append(files, ChangedFile{Path: p, HeadContent: head, BaseContent: base})
	}
	return files, nil
}

// gitLines runs a git subcommand in repoDir and returns its non-empty output
// lines.
func gitLines(repoDir string, args ...string) ([]string, error) {
	cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("git %s: %w\n%s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines, nil
}
