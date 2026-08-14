package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q"},
		{"config", "user.email", "t@t.t"},
		{"config", "user.name", "t"},
	} {
		run(t, dir, args...)
	}
	return dir
}

func run(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The index, not the worktree, is what the commit will contain. A user who
// staged a clean version and then kept editing must be judged on what they
// staged — scanning the worktree would block a commit over lines that aren't
// in it (and worse, pass one whose staged content is dirty).
func TestStaged_ScansTheIndexNotTheWorktree(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"a\" {}\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "init")

	write(t, dir, "main.tf", "resource \"aws_vpc\" \"staged\" {}\n")
	run(t, dir, "add", "main.tf")
	// Keep editing after staging.
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"worktree_only\" {}\n")

	files, err := StagedTerraformFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if got := string(files[0].HeadContent); got != "resource \"aws_vpc\" \"staged\" {}\n" {
		t.Errorf("head must be the staged blob, got %q", got)
	}
	if got := string(files[0].BaseContent); got != "resource \"aws_vpc\" \"a\" {}\n" {
		t.Errorf("base must be HEAD's version, got %q", got)
	}
}

// A pre-commit hook runs on the very first commit of a repo too, where HEAD
// doesn't exist. Everything staged is simply new.
func TestStaged_WorksOnTheFirstCommit(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"a\" {}\n")
	run(t, dir, "add", ".")

	files, err := StagedTerraformFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d files, want 1", len(files))
	}
	if files[0].BaseContent != nil {
		t.Error("with no HEAD, base must be nil (a new file)")
	}
}

func TestStaged_NothingStagedMeansNothingToScan(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"a\" {}\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "init")
	// Unstaged edit only.
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"edited\" {}\n")

	files, err := StagedTerraformFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("an unstaged edit is not part of the commit; got %d files", len(files))
	}
}

func TestStaged_DeletionIsSkipped(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"a\" {}\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "init")
	run(t, dir, "rm", "-q", "main.tf")

	files, err := StagedTerraformFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("a staged deletion has no content to scan; got %d files", len(files))
	}
}

// Untracked files are the whole reason this mode exists apart from --staged:
// the brand-new main.tf nobody has git-added yet is exactly what "what would
// the firewall say?" is asking about.
func TestUncommitted_IncludesUntrackedStagedAndUnstaged(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, "committed.tf", "resource \"aws_vpc\" \"a\" {}\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "init")

	write(t, dir, "committed.tf", "resource \"aws_vpc\" \"edited\" {}\n") // unstaged edit
	write(t, dir, "staged.tf", "resource \"aws_vpc\" \"s\" {}\n")
	run(t, dir, "add", "staged.tf")
	write(t, dir, "untracked.tf", "resource \"aws_vpc\" \"u\" {}\n")

	files, err := UncommittedTerraformFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]ChangedFile{}
	for _, f := range files {
		byPath[f.Path] = f
	}
	if len(byPath) != 3 {
		t.Fatalf("got %v, want committed.tf, staged.tf, untracked.tf", keysOf(byPath))
	}
	if got := string(byPath["committed.tf"].HeadContent); got != "resource \"aws_vpc\" \"edited\" {}\n" {
		t.Errorf("head must be the worktree content, got %q", got)
	}
	if byPath["committed.tf"].BaseContent == nil {
		t.Error("a tracked file must carry HEAD's version as base")
	}
	if byPath["untracked.tf"].BaseContent != nil {
		t.Error("an untracked file has no base")
	}
}

func TestUncommitted_RespectsGitignore(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, ".gitignore", ".terraform/\n")
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"a\" {}\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "init")
	// Provider caches hold vendored .tf files; scanning them would bury the
	// user's own findings under a module vendor tree they don't own.
	write(t, dir, ".terraform/modules/x/main.tf", "resource \"aws_db_instance\" \"p\" { password = \"x\" }\n")

	files, err := UncommittedTerraformFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("gitignored files must not be scanned; got %v", keysOf(byPathMap(files)))
	}
}

func TestUncommitted_CleanTreeFindsNothing(t *testing.T) {
	dir := gitRepo(t)
	write(t, dir, "main.tf", "resource \"aws_vpc\" \"a\" {}\n")
	run(t, dir, "add", ".")
	run(t, dir, "commit", "-qm", "init")

	files, err := UncommittedTerraformFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 0 {
		t.Errorf("a clean tree has no uncommitted changes; got %d files", len(files))
	}
}

func byPathMap(files []ChangedFile) map[string]ChangedFile {
	m := map[string]ChangedFile{}
	for _, f := range files {
		m[f.Path] = f
	}
	return m
}

func keysOf(m map[string]ChangedFile) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
