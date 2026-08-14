package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func TestRequestSecondReviewerIfCritical_NoOpWithoutConfiguredReviewers(t *testing.T) {
	// No GITHUB_TOKEN/GITHUB_REPOSITORY set, and no reviewers configured —
	// this must return immediately without trying to build a PR client
	// (which would otherwise fail loudly on missing env vars).
	findings := []report.Finding{{Severity: report.SeverityCritical}}
	requestSecondReviewerIfCritical(findings, config{})
}

func TestRequestSecondReviewerIfCritical_NoOpWithoutCriticalFinding(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("PR_NUMBER", "1")

	findings := []report.Finding{{Severity: report.SeverityHigh}}
	cfg := config{RequireSecondReviewerUsers: []string{"alice"}}
	requestSecondReviewerIfCritical(findings, cfg)

	if called {
		t.Error("expected no API call when no finding is critical severity")
	}
}

func TestRequestSecondReviewerIfCritical_RequestsReviewersOnCriticalFinding(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("PR_NUMBER", "7")

	origAPIBase := githubAPIBaseForTest
	githubAPIBaseForTest = srv.URL
	defer func() { githubAPIBaseForTest = origAPIBase }()

	findings := []report.Finding{{Severity: report.SeverityCritical}}
	cfg := config{RequireSecondReviewerUsers: []string{"alice"}}
	requestSecondReviewerIfCritical(findings, cfg)

	if gotPath != "/repos/owner/repo/pulls/7/requested_reviewers" {
		t.Errorf("expected a requested_reviewers call, got path %q", gotPath)
	}
}
