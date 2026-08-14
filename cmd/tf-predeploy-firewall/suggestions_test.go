package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func fixableFinding() report.Finding {
	return report.Finding{
		File:     "rds.tf",
		Line:     2,
		Category: report.CategoryMissingLifecycle,
		Severity: report.SeverityMedium,
		Resource: "aws_db_instance.prod",
		Message:  "no prevent_destroy guard",
		Fix: &report.Fix{
			StartLine: 2, EndLine: 2,
			Lines: []string{`resource "aws_db_instance" "prod" {`, "  lifecycle {", "    prevent_destroy = true", "  }"},
		},
	}
}

// suggestionServer answers the three endpoints and captures the review.
func suggestionServer(t *testing.T, patch string) (*httptest.Server, *map[string]any) {
	t.Helper()
	var review map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/files"):
			out := []map[string]string{}
			if r.URL.Query().Get("page") == "1" {
				out = append(out, map[string]string{"filename": "rds.tf", "patch": patch})
			}
			json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet:
			json.NewEncoder(w).Encode([]map[string]string{})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reviews"):
			json.NewDecoder(r.Body).Decode(&review)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &review
}

func withPRContext(t *testing.T, srv *httptest.Server) {
	t.Helper()
	t.Setenv("GITHUB_TOKEN", "test-token")
	t.Setenv("GITHUB_REPOSITORY", "owner/repo")
	t.Setenv("PR_NUMBER", "5")

	orig := githubAPIBaseForTest
	githubAPIBaseForTest = srv.URL
	t.Cleanup(func() { githubAPIBaseForTest = orig })
}

func TestPostSuggestions_EndToEnd(t *testing.T) {
	srv, review := suggestionServer(t, "@@ -1,3 +1,4 @@\n+resource \"aws_db_instance\" \"prod\" {\n+  identifier = \"prod\"\n+}\n")
	withPRContext(t, srv)

	postSuggestions([]report.Finding{fixableFinding()})

	if *review == nil {
		t.Fatal("expected a review to be posted")
	}
	comments := (*review)["comments"].([]any)
	if len(comments) != 1 {
		t.Fatalf("expected 1 inline comment, got %d", len(comments))
	}
	body := comments[0].(map[string]any)["body"].(string)
	if !strings.Contains(body, "```suggestion") {
		t.Errorf("the comment carries no applicable suggestion:\n%s", body)
	}
	if !strings.Contains(body, "prevent_destroy = true") {
		t.Errorf("the suggestion doesn't contain the fix:\n%s", body)
	}
}

// An accepted finding is a decision already made; handing someone a button
// to un-accept it would undo the point of the baseline.
func TestPostSuggestions_SkipsWaivedFindings(t *testing.T) {
	srv, review := suggestionServer(t, "@@ -1,3 +1,4 @@\n+x\n")
	withPRContext(t, srv)

	f := fixableFinding()
	f.Waived = true
	f.WaiverNote = "accepted in baseline"
	postSuggestions([]report.Finding{f})

	if *review != nil {
		t.Error("a waived finding must not produce an inline suggestion")
	}
}

// Most findings have no exact fix. That path must cost nothing — not even
// the API calls needed to work out where the diff is.
func TestPostSuggestions_NoNetworkWhenNothingIsFixable(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()
	withPRContext(t, srv)

	postSuggestions([]report.Finding{{
		File: "rds.tf", Line: 1, Category: report.CategoryTutorialPattern,
		Severity: report.SeverityHigh, Resource: "aws_security_group.web",
		Message: "0.0.0.0/0",
	}})

	if called {
		t.Error("expected no API traffic when no finding carries a fix")
	}
}

// The whole feature is a convenience layered on the summary comment. If it
// fails, the scan's verdict must be unaffected — this test exists to catch
// a future refactor that makes it fatal.
func TestPostSuggestions_SurvivesAnAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	withPRContext(t, srv)

	postSuggestions([]report.Finding{fixableFinding()}) // must not panic or exit
}

func TestPostSuggestions_RespectsTheInlineCap(t *testing.T) {
	var patch strings.Builder
	patch.WriteString("@@ -1,1 +1,200 @@\n")
	for i := 0; i < 200; i++ {
		patch.WriteString("+line\n")
	}
	srv, review := suggestionServer(t, patch.String())
	withPRContext(t, srv)

	var findings []report.Finding
	for i := 1; i <= maxInlineSuggestions+5; i++ {
		f := fixableFinding()
		f.Resource = "aws_db_instance.db" + string(rune('a'+i))
		f.Fix.StartLine, f.Fix.EndLine = i, i
		findings = append(findings, f)
	}
	postSuggestions(findings)

	got := len((*review)["comments"].([]any))
	if got != maxInlineSuggestions {
		t.Errorf("posted %d inline comments, want the cap of %d", got, maxInlineSuggestions)
	}
}
