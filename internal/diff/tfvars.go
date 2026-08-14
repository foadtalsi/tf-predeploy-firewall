package diff

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Collecting .tfvars files, in each of the four modes the scanner runs in.
//
// They need their own pathspecs because ChangedTerraformFiles' "*.tf" glob
// does not match them, and because two shapes are in use: terraform.tfvars
// / *.auto.tfvars (HCL) and their .json equivalents.
var tfvarsPathspecs = []string{"*.tfvars", "*.tfvars.json"}

// isTfvars mirrors the pathspecs above for the walk- and worktree-based
// modes, where git does not do the matching for us.
func isTfvars(path string) bool {
	return strings.HasSuffix(path, ".tfvars") || strings.HasSuffix(path, ".tfvars.json")
}

// ChangedTfvarsFiles returns every .tfvars file that differs between
// baseRef and headRef.
func ChangedTfvarsFiles(repoDir, baseRef, headRef string) ([]ChangedFile, error) {
	if err := validateRefs(repoDir, baseRef, headRef); err != nil {
		return nil, err
	}

	seen := map[string]bool{}
	var files []ChangedFile
	for _, spec := range tfvarsPathspecs {
		paths, err := changedPathsMatching(repoDir, baseRef, headRef, spec)
		if err != nil {
			return nil, err
		}
		for _, p := range paths {
			if seen[p] {
				continue
			}
			seen[p] = true
			head, err := showFile(repoDir, headRef, p)
			if err != nil {
				continue // deleted at head; nothing to scan
			}
			files = append(files, ChangedFile{Path: p, HeadContent: head})
		}
	}
	return files, nil
}

// StagedTfvarsFiles returns every .tfvars file with staged changes.
func StagedTfvarsFiles(repoDir string) ([]ChangedFile, error) {
	return multiSpec(repoDir, stagedFiles)
}

// UncommittedTfvarsFiles returns every .tfvars file differing from HEAD in
// the working tree, untracked ones included.
//
// Untracked matters more here than anywhere else: the whole point of a
// pre-commit check on a .tfvars file is to catch the secret in the moment
// before `git add` makes it part of the repository.
func UncommittedTfvarsFiles(repoDir string) ([]ChangedFile, error) {
	return multiSpec(repoDir, uncommittedFiles)
}

func multiSpec(repoDir string, collect func(string, string) ([]ChangedFile, error)) ([]ChangedFile, error) {
	seen := map[string]bool{}
	var out []ChangedFile
	for _, spec := range tfvarsPathspecs {
		files, err := collect(repoDir, spec)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if seen[f.Path] {
				continue
			}
			seen[f.Path] = true
			out = append(out, f)
		}
	}
	return out, nil
}

// AllTfvarsFiles walks repoDir for every .tfvars file — the full-repo-scan
// equivalent, for a scheduled audit of already-merged code.
func AllTfvarsFiles(repoDir string) ([]ChangedFile, error) {
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
		if !isTfvars(path) {
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
		return nil, fmt.Errorf("walking %s for .tfvars files: %w", repoDir, err)
	}
	return files, nil
}
