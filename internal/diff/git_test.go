package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// makeRepo creates a temporary git repo, commits baseTF at basePath,
// then commits headTF at headPath (may be the same file), and returns
// the repo dir, base ref ("HEAD~1"), and head ref ("HEAD").
func makeRepo(t *testing.T, basePath, baseTF, headPath, headTF string) (repoDir, baseRef, headRef string) {
	t.Helper()
	dir := t.TempDir()

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=t@t.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=t@t.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	git("init", "-b", "main")
	git("config", "user.email", "t@t.com")
	git("config", "user.name", "test")

	writeFile(t, filepath.Join(dir, basePath), baseTF)
	git("add", ".")
	git("commit", "-m", "base")

	writeFile(t, filepath.Join(dir, headPath), headTF)
	git("add", ".")
	git("commit", "-m", "head")

	return dir, "HEAD~1", "HEAD"
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

const baseTF = `
resource "aws_instance" "base" {
  ami = "ami-base"
}
`

const headTF = `
resource "aws_instance" "head" {
  ami = "ami-head"
}
`

func TestChangedTerraformFiles_BasicDiff(t *testing.T) {
	dir, base, head := makeRepo(t, "main.tf", baseTF, "main.tf", headTF)

	files, err := ChangedTerraformFiles(dir, base, head)
	if err != nil {
		t.Fatalf("ChangedTerraformFiles: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("expected 1 changed file, got %d", len(files))
	}
	if files[0].Path != "main.tf" {
		t.Errorf("unexpected path: %s", files[0].Path)
	}
	if !strings.Contains(string(files[0].HeadContent), "ami-head") {
		t.Error("head content should contain ami-head")
	}
	if !strings.Contains(string(files[0].BaseContent), "ami-base") {
		t.Error("base content should contain ami-base")
	}
}

func TestChangedTerraformFiles_NewFile(t *testing.T) {
	dir, base, head := makeRepo(t, "existing.tf", baseTF, "new.tf", headTF)

	files, err := ChangedTerraformFiles(dir, base, head)
	if err != nil {
		t.Fatalf("ChangedTerraformFiles: %v", err)
	}
	if len(files) != 1 || files[0].Path != "new.tf" {
		t.Fatalf("expected new.tf, got %v", files)
	}
	if files[0].BaseContent != nil {
		t.Error("BaseContent should be nil for a brand-new file")
	}
}

func TestChangedTerraformFiles_NonTFFilesIgnored(t *testing.T) {
	dir, base, head := makeRepo(t, "README.md", "# base", "README.md", "# head")

	files, err := ChangedTerraformFiles(dir, base, head)
	if err != nil {
		t.Fatalf("ChangedTerraformFiles: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected no .tf files, got %d", len(files))
	}
}

func TestChangedTerraformFiles_SubdirectoryTF(t *testing.T) {
	dir, base, head := makeRepo(t, "modules/rds/main.tf", baseTF, "modules/rds/main.tf", headTF)

	files, err := ChangedTerraformFiles(dir, base, head)
	if err != nil {
		t.Fatalf("ChangedTerraformFiles: %v", err)
	}
	if len(files) != 1 || files[0].Path != "modules/rds/main.tf" {
		t.Fatalf("expected modules/rds/main.tf, got %v", files)
	}
}

func TestChangedTerraformFiles_InvalidRef(t *testing.T) {
	dir, _, _ := makeRepo(t, "main.tf", baseTF, "main.tf", headTF)

	_, err := ChangedTerraformFiles(dir, "nonexistent-ref", "HEAD")
	if err == nil {
		t.Fatal("expected error for nonexistent ref, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent-ref") {
		t.Errorf("error should mention the bad ref, got: %v", err)
	}
}
