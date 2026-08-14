package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/licensing"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func TestApplyWaivers_MatchesByCategoryResourceFile(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]licensing.Waiver{
			{Category: "missing_lifecycle", Resource: "aws_db_instance.legacy", FilePath: "main.tf", Justification: "ticketed in INFRA-42"},
		})
	}))
	defer srv.Close()

	findings := []report.Finding{
		{Category: report.CategoryMissingLifecycle, Resource: "aws_db_instance.legacy", File: "main.tf", Severity: report.SeverityCritical},
		// Same category+file, different resource — must NOT match.
		{Category: report.CategoryMissingLifecycle, Resource: "aws_db_instance.other", File: "main.tf", Severity: report.SeverityCritical},
	}

	got := applyWaivers(findings, "test-key", srv.URL)

	if !got[0].Waived || got[0].WaiverNote != "ticketed in INFRA-42" {
		t.Errorf("expected the matching finding to be waived with its justification, got %#v", got[0])
	}
	if got[1].Waived {
		t.Errorf("expected the non-matching finding (different resource) to remain active, got %#v", got[1])
	}
}

func TestApplyWaivers_LineNumberDoesNotAffectMatch(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]licensing.Waiver{
			{Category: "missing_lifecycle", Resource: "aws_db_instance.legacy", FilePath: "main.tf", Justification: "accepted"},
		})
	}))
	defer srv.Close()

	// The finding's line has drifted (e.g. code added above it in the
	// file) since the waiver was created — matching is deliberately NOT
	// line-sensitive, so this must still match.
	findings := []report.Finding{
		{Category: report.CategoryMissingLifecycle, Resource: "aws_db_instance.legacy", File: "main.tf", Line: 42, Severity: report.SeverityCritical},
	}

	got := applyWaivers(findings, "test-key", srv.URL)
	if !got[0].Waived {
		t.Error("expected a line-number drift to not prevent the waiver from matching")
	}
}

func TestApplyWaivers_NoRepoEnvVarLeavesFindingsUntouched(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "")

	findings := []report.Finding{{Category: report.CategoryMissingLifecycle, Resource: "x", File: "main.tf"}}
	got := applyWaivers(findings, "test-key", "http://127.0.0.1:1")
	if got[0].Waived {
		t.Error("expected no waiving without GITHUB_REPOSITORY set")
	}
}

func TestApplyWaivers_FailsOpenOnNetworkError(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")

	findings := []report.Finding{{Category: report.CategoryMissingLifecycle, Resource: "x", File: "main.tf", Severity: report.SeverityCritical}}
	got := applyWaivers(findings, "test-key", "http://127.0.0.1:1") // nothing listening

	if got[0].Waived {
		t.Error("expected findings unmodified when the control plane is unreachable")
	}
}
