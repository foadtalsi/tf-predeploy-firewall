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
