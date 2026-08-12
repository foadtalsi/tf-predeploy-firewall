package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/licensing"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func TestApplyOrgPolicy_OverridesLocalConfig(t *testing.T) {
	t.Setenv("SCANNER_BLOCK_THRESHOLD", "")
	t.Setenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		threshold := "critical"
		blastRadius := 3
		json.NewEncoder(w).Encode(licensing.Policy{
			BlockThreshold:           &threshold,
			IgnoreRules:              []string{"tutorial_pattern"},
			PlanBlastRadiusThreshold: &blastRadius,
		})
	}))
	defer srv.Close()

	cfg := config{BlockThreshold: report.SeverityHigh, PlanBlastRadiusThreshold: 10}
	applyOrgPolicy(&cfg, "test-key", srv.URL)

	if cfg.BlockThreshold != report.SeverityCritical {
		t.Errorf("expected policy to override block threshold to critical, got %s", cfg.BlockThreshold)
	}
	if cfg.PlanBlastRadiusThreshold != 3 {
		t.Errorf("expected policy to override blast radius to 3, got %d", cfg.PlanBlastRadiusThreshold)
	}
	if len(cfg.IgnoreRules) != 1 || cfg.IgnoreRules[0] != report.CategoryTutorialPattern {
		t.Errorf("expected policy to replace ignore rules, got %v", cfg.IgnoreRules)
	}
}

func TestApplyOrgPolicy_EnvVarWinsOverPolicy(t *testing.T) {
	t.Setenv("SCANNER_BLOCK_THRESHOLD", "low")
	t.Setenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		threshold := "critical"
		json.NewEncoder(w).Encode(licensing.Policy{BlockThreshold: &threshold})
	}))
	defer srv.Close()

	cfg := config{BlockThreshold: report.SeverityHigh}
	applyOrgPolicy(&cfg, "test-key", srv.URL)

	if cfg.BlockThreshold != report.SeverityHigh {
		t.Errorf("expected env var precedence to leave block threshold untouched by policy, got %s", cfg.BlockThreshold)
	}
}

func TestApplyOrgPolicy_NoPolicyLeavesConfigUntouched(t *testing.T) {
	t.Setenv("SCANNER_BLOCK_THRESHOLD", "")
	t.Setenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(licensing.Policy{})
	}))
	defer srv.Close()

	cfg := config{BlockThreshold: report.SeverityHigh, PlanBlastRadiusThreshold: 10}
	applyOrgPolicy(&cfg, "test-key", srv.URL)

	if cfg.BlockThreshold != report.SeverityHigh || cfg.PlanBlastRadiusThreshold != 10 {
		t.Errorf("expected no changes when the org has no policy, got %+v", cfg)
	}
}

func TestApplyOrgPolicy_FailsOpenOnNetworkError(t *testing.T) {
	cfg := config{BlockThreshold: report.SeverityHigh, PlanBlastRadiusThreshold: 10}
	applyOrgPolicy(&cfg, "test-key", "http://127.0.0.1:1") // nothing listening

	if cfg.BlockThreshold != report.SeverityHigh || cfg.PlanBlastRadiusThreshold != 10 {
		t.Errorf("expected config untouched when the control plane is unreachable, got %+v", cfg)
	}
}

func TestApplyOrgPolicy_ReviewerListsOverrideLocalConfig(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(licensing.Policy{
			RequireSecondReviewerUsers: []string{"alice"},
			RequireSecondReviewerTeams: []string{"security-team"},
		})
	}))
	defer srv.Close()

	cfg := config{BlockThreshold: report.SeverityHigh}
	applyOrgPolicy(&cfg, "test-key", srv.URL)

	if len(cfg.RequireSecondReviewerUsers) != 1 || cfg.RequireSecondReviewerUsers[0] != "alice" {
		t.Errorf("expected policy to set reviewer users, got %v", cfg.RequireSecondReviewerUsers)
	}
	if len(cfg.RequireSecondReviewerTeams) != 1 || cfg.RequireSecondReviewerTeams[0] != "security-team" {
		t.Errorf("expected policy to set reviewer teams, got %v", cfg.RequireSecondReviewerTeams)
	}
}

func TestApplyOrgPolicy_CustomRulesYAMLOverridesLocalConfig(t *testing.T) {
	customRules := "custom_rules:\n  - id: no-iam-users\n    resource_type: aws_iam_user\n    severity: medium\n    message: x\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(licensing.Policy{CustomRulesYAML: &customRules})
	}))
	defer srv.Close()

	cfg := config{BlockThreshold: report.SeverityHigh}
	applyOrgPolicy(&cfg, "test-key", srv.URL)

	if cfg.CustomRulesYAMLOverride != customRules {
		t.Errorf("expected CustomRulesYAMLOverride to be set from org policy, got %q", cfg.CustomRulesYAMLOverride)
	}
}
