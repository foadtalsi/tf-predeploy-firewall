package licensing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRecordScan_Allowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}
		var body recordScanRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if body.RepoFullName != "acme/infra" {
			t.Errorf("unexpected repo_full_name: %s", body.RepoFullName)
		}
		json.NewEncoder(w).Encode(recordScanResponse{Allowed: true})
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	allowed, _, err := client.RecordScan(ScanResult{RepoFullName: "acme/infra", FindingCount: 3, Blocked: false})
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
	if !allowed {
		t.Error("expected allowed=true")
	}
}

// TestRecordScan_SendsFindingDetail guards against the control plane's
// dashboard (Reports/Trends/Audit Log) silently going back to showing only
// a bare count: previously ScanResult only carried FindingCount, so an
// admin drilling into a scan had no way to see what was actually found.
func TestRecordScan_SendsFindingDetail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body recordScanRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decoding request: %v", err)
		}
		if len(body.Findings) != 1 {
			t.Fatalf("expected 1 finding in the request body, got %d", len(body.Findings))
		}
		f := body.Findings[0]
		if f.Category != "missing_lifecycle" || f.Severity != "critical" || f.Resource != "aws_db_instance.primary" ||
			f.FilePath != "database.tf" || f.Line != 3 || f.Message != "missing prevent_destroy" {
			t.Errorf("finding payload didn't round-trip correctly: %#v", f)
		}
		json.NewEncoder(w).Encode(recordScanResponse{Allowed: true})
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	_, _, err := client.RecordScan(ScanResult{
		RepoFullName: "acme/infra",
		FindingCount: 1,
		Blocked:      true,
		Findings: []FindingSummary{
			{Category: "missing_lifecycle", Severity: "critical", Resource: "aws_db_instance.primary", FilePath: "database.tf", Line: 3, Message: "missing prevent_destroy"},
		},
	})
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
}

func TestRecordScan_QuotaExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(recordScanResponse{Allowed: false, Reason: "plan quota exceeded"})
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	allowed, reason, err := client.RecordScan(ScanResult{RepoFullName: "acme/infra"})
	if err != nil {
		t.Fatalf("RecordScan: %v", err)
	}
	if allowed {
		t.Error("expected allowed=false")
	}
	if reason != "plan quota exceeded" {
		t.Errorf("unexpected reason: %s", reason)
	}
}

func TestRecordScan_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := NewClient("bad-key", srv.URL)
	_, _, err := client.RecordScan(ScanResult{RepoFullName: "acme/infra"})
	if err == nil {
		t.Fatal("expected an error for an unauthorized response")
	}
}

func TestRecordScan_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	_, _, err := client.RecordScan(ScanResult{RepoFullName: "acme/infra"})
	if err == nil {
		t.Fatal("expected an error for a 500 response")
	}
}
