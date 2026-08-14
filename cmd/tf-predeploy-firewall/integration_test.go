package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildScanner compiles the scanner binary once per test run and returns
// its path. This is a black-box test: it exercises the exact wiring in
// main() — flag parsing, config loading, the static scan, the optional
// --plan-json merge, and the exit code — rather than calling internal
// functions directly, so a regression in how main() wires those pieces
// together actually fails a test instead of only being caught by manual
// E2E runs.
func buildScanner(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "tf-predeploy-firewall-test")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("building scanner binary: %v\n%s", err, out)
	}
	return bin
}

// initGitRepoWithCommits creates a temp git repo with a base commit and a
// head commit containing the given main.tf variants, returning the repo dir.
func initGitRepoWithCommits(t *testing.T, baseTF, headTF string) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q", "-b", "main")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")

	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(baseTF), 0644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "base")

	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(headTF), 0644); err != nil {
		t.Fatal(err)
	}
	run("add", "-A")
	run("commit", "-q", "-m", "head")

	return dir
}

func TestIntegration_StaticScanFindsAndBlocks(t *testing.T) {
	bin := buildScanner(t)
	repoDir := initGitRepoWithCommits(t,
		`resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}`,
		`resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
resource "aws_db_instance" "prod" {
  identifier = "prod-db"
  password   = "changeme"
}`)

	cmd := exec.Command(bin, "--repo-dir", repoDir, "--base-ref", "HEAD~1", "--head-ref", "HEAD")
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1 (blocked), got err=%v, output:\n%s", err, out)
	}
	if !strings.Contains(string(out), "hardcoded string literal") {
		t.Errorf("expected the credential finding in output, got:\n%s", out)
	}
	if !strings.Contains(string(out), "Merge blocked") {
		t.Errorf("expected 'Merge blocked' in output, got:\n%s", out)
	}
}

func TestIntegration_NoFindingsExitsZero(t *testing.T) {
	bin := buildScanner(t)
	// enable_dns_hostnames is a known, non-ForceNew aws_vpc attribute — a
	// clean in-place update that should trip none of the four static rules.
	repoDir := initGitRepoWithCommits(t,
		`resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}`,
		`resource "aws_vpc" "main" {
  cidr_block            = "10.0.0.0/16"
  enable_dns_hostnames  = true
}`)

	cmd := exec.Command(bin, "--repo-dir", repoDir, "--base-ref", "HEAD~1", "--head-ref", "HEAD")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected exit code 0, got err=%v, output:\n%s", err, out)
	}
	if !strings.Contains(string(out), "No risk patterns detected") {
		t.Errorf("expected the clean-scan message, got:\n%s", out)
	}
}

func TestIntegration_PlanJSONMergesAndDeduplicates(t *testing.T) {
	bin := buildScanner(t)
	repoDir := initGitRepoWithCommits(t,
		`resource "aws_db_instance" "prod" {
  identifier = "prod-db"
  engine     = "postgres"
}`,
		`resource "aws_db_instance" "prod" {
  identifier = "prod-db"
  engine     = "mysql"
}`)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(wd, "..", "..", "testdata", "plans", "sample_plan.json")

	cmd := exec.Command(bin, "--repo-dir", repoDir, "--base-ref", "HEAD~1", "--head-ref", "HEAD", "--plan-json", planPath)
	out, err := cmd.CombinedOutput()
	output := string(out)

	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("expected exit code 1, got err=%v, output:\n%s", err, output)
	}

	if !strings.Contains(output, "Confirmed destroy/replace") {
		t.Errorf("expected a phase-2 confirmed-replace finding in output, got:\n%s", output)
	}
	if strings.Contains(output, "ForceNew change on stateful resource") {
		t.Errorf("expected the phase-1 ForceNew heuristic finding to be deduplicated away, got:\n%s", output)
	}
}

func TestIntegration_MissingPlanJSONFileExitsWithError(t *testing.T) {
	bin := buildScanner(t)
	repoDir := initGitRepoWithCommits(t,
		`resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }`,
		`resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_vpc" "extra" { cidr_block = "10.1.0.0/16" }`)

	cmd := exec.Command(bin, "--repo-dir", repoDir, "--base-ref", "HEAD~1", "--head-ref", "HEAD",
		"--plan-json", filepath.Join(repoDir, "does-not-exist.json"))
	out, err := cmd.CombinedOutput()

	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 (config/setup error), got err=%v, output:\n%s", err, out)
	}
}
