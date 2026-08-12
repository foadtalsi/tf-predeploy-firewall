package licensing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetPolicy_NoPolicySet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Policy{}) // control plane returns an empty object when no policy exists
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	policy, err := client.GetPolicy("")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if policy != nil {
		t.Errorf("expected nil policy when none is set, got %#v", policy)
	}
}

func TestGetPolicy_WithOverrides(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}
		threshold := "critical"
		blastRadius := 5
		customRules := "custom_rules:\n  - id: no-iam-users\n    resource_type: aws_iam_user\n    severity: medium\n    message: x\n"
		json.NewEncoder(w).Encode(Policy{
			BlockThreshold:           &threshold,
			IgnoreRules:              []string{"tutorial_pattern"},
			PlanBlastRadiusThreshold: &blastRadius,
			CustomRulesYAML:          &customRules,
		})
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	policy, err := client.GetPolicy("")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if policy == nil {
		t.Fatal("expected a non-nil policy")
	}
	if *policy.BlockThreshold != "critical" {
		t.Errorf("unexpected block threshold: %v", *policy.BlockThreshold)
	}
	if len(policy.IgnoreRules) != 1 || policy.IgnoreRules[0] != "tutorial_pattern" {
		t.Errorf("unexpected ignore rules: %v", policy.IgnoreRules)
	}
	if policy.PlanBlastRadiusThreshold == nil || *policy.PlanBlastRadiusThreshold != 5 {
		t.Errorf("unexpected blast radius threshold: %v", policy.PlanBlastRadiusThreshold)
	}
	if policy.CustomRulesYAML == nil || !strings.Contains(*policy.CustomRulesYAML, "no-iam-users") {
		t.Errorf("unexpected custom rules yaml: %v", policy.CustomRulesYAML)
	}
}

// TestGetPolicy_SendsRepoQueryParam guards the control plane's ability to
// merge a repo-specific override on top of the org-wide policy: it can
// only do that if the CLI actually tells it which repo is scanning.
func TestGetPolicy_SendsRepoQueryParam(t *testing.T) {
	var gotRepo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRepo = r.URL.Query().Get("repo")
		json.NewEncoder(w).Encode(Policy{})
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	if _, err := client.GetPolicy("acme/infra"); err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if gotRepo != "acme/infra" {
		t.Errorf("expected repo query param %q, got %q", "acme/infra", gotRepo)
	}
}

func TestGetPolicy_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := NewClient("bad-key", srv.URL)
	_, err := client.GetPolicy("")
	if err == nil {
		t.Fatal("expected an error for an unauthorized response")
	}
}
