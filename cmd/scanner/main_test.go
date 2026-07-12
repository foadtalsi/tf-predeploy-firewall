package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func TestBlockedBy(t *testing.T) {
	findings := []report.Finding{
		{Severity: report.SeverityMedium},
		{Severity: report.SeverityLow},
	}
	if blockedBy(findings, report.SeverityHigh) {
		t.Error("expected not blocked: nothing reaches high")
	}
	if !blockedBy(findings, report.SeverityMedium) {
		t.Error("expected blocked: a medium finding meets a medium threshold")
	}
}

func TestLoadConfig_MissingFileFallsBackToDefaults(t *testing.T) {
	cfg, err := loadConfig(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BlockThreshold != report.SeverityHigh {
		t.Errorf("expected default block threshold 'high', got %q", cfg.BlockThreshold)
	}
	if cfg.PlanBlastRadiusThreshold != 10 {
		t.Errorf("expected default blast radius threshold 10, got %d", cfg.PlanBlastRadiusThreshold)
	}
}

func TestLoadConfig_YAMLOverridesDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	yamlContent := "block_threshold: critical\nplan_blast_radius_threshold: 3\nignore_rules: [tutorial_pattern]\n"
	if err := os.WriteFile(path, []byte(yamlContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BlockThreshold != report.SeverityCritical {
		t.Errorf("expected 'critical', got %q", cfg.BlockThreshold)
	}
	if cfg.PlanBlastRadiusThreshold != 3 {
		t.Errorf("expected 3, got %d", cfg.PlanBlastRadiusThreshold)
	}
	if len(cfg.IgnoreRules) != 1 || cfg.IgnoreRules[0] != report.CategoryTutorialPattern {
		t.Errorf("expected ignore_rules=[tutorial_pattern], got %v", cfg.IgnoreRules)
	}
}

func TestLoadConfig_EnvOverridesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte("block_threshold: low\nplan_blast_radius_threshold: 5\n"), 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SCANNER_BLOCK_THRESHOLD", "critical")
	t.Setenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD", "20")

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.BlockThreshold != report.SeverityCritical {
		t.Errorf("expected env override 'critical', got %q", cfg.BlockThreshold)
	}
	if cfg.PlanBlastRadiusThreshold != 20 {
		t.Errorf("expected env override 20, got %d", cfg.PlanBlastRadiusThreshold)
	}
}

func TestLoadConfig_InvalidBlastRadiusEnv(t *testing.T) {
	t.Setenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD", "not-a-number")
	_, err := loadConfig(filepath.Join(t.TempDir(), "does-not-exist.yml"))
	if err == nil {
		t.Fatal("expected an error for a non-integer SCANNER_PLAN_BLAST_RADIUS_THRESHOLD")
	}
}

func TestEnvOr(t *testing.T) {
	t.Setenv("TF_FIREWALL_TEST_VAR", "")
	if got := envOr("TF_FIREWALL_TEST_VAR", "fallback"); got != "fallback" {
		t.Errorf("expected fallback for empty env var, got %q", got)
	}
	t.Setenv("TF_FIREWALL_TEST_VAR", "set-value")
	if got := envOr("TF_FIREWALL_TEST_VAR", "fallback"); got != "set-value" {
		t.Errorf("expected env value, got %q", got)
	}
}

func TestPRNumberFromEvent_PRNumberEnvTakesPriority(t *testing.T) {
	t.Setenv("PR_NUMBER", "42")
	t.Setenv("GITHUB_EVENT_PATH", "")
	n, err := prNumberFromEvent()
	if err != nil {
		t.Fatalf("prNumberFromEvent: %v", err)
	}
	if n != 42 {
		t.Errorf("expected 42, got %d", n)
	}
}

func TestPRNumberFromEvent_FromEventPayload(t *testing.T) {
	t.Setenv("PR_NUMBER", "")
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(`{"pull_request": {"number": 7}}`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", path)

	n, err := prNumberFromEvent()
	if err != nil {
		t.Fatalf("prNumberFromEvent: %v", err)
	}
	if n != 7 {
		t.Errorf("expected 7, got %d", n)
	}
}

func TestPRNumberFromEvent_MissingEverything(t *testing.T) {
	t.Setenv("PR_NUMBER", "")
	t.Setenv("GITHUB_EVENT_PATH", "")
	if _, err := prNumberFromEvent(); err == nil {
		t.Fatal("expected an error when neither PR_NUMBER nor GITHUB_EVENT_PATH is set")
	}
}

func TestPRNumberFromEvent_NonPullRequestEvent(t *testing.T) {
	t.Setenv("PR_NUMBER", "")
	path := filepath.Join(t.TempDir(), "event.json")
	if err := os.WriteFile(path, []byte(`{"ref": "refs/heads/main"}`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_EVENT_PATH", path)

	if _, err := prNumberFromEvent(); err == nil {
		t.Fatal("expected an error for an event payload with no pull_request.number")
	}
}
