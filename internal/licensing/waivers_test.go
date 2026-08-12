package licensing

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGetWaivers_SendsRepoQueryParamAndParsesResponse(t *testing.T) {
	var gotRepo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Errorf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
		}
		gotRepo = r.URL.Query().Get("repo")
		json.NewEncoder(w).Encode([]Waiver{
			{Category: "missing_lifecycle", Resource: "aws_db_instance.legacy", FilePath: "main.tf", Justification: "ticketed in INFRA-42"},
		})
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	waivers, err := client.GetWaivers("acme/infra")
	if err != nil {
		t.Fatalf("GetWaivers: %v", err)
	}
	if gotRepo != "acme/infra" {
		t.Errorf("expected repo query param %q, got %q", "acme/infra", gotRepo)
	}
	if len(waivers) != 1 || waivers[0].Justification != "ticketed in INFRA-42" {
		t.Errorf("unexpected waivers: %#v", waivers)
	}
}

func TestGetWaivers_EmptyWhenNoneConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]Waiver{})
	}))
	defer srv.Close()

	client := NewClient("test-key", srv.URL)
	waivers, err := client.GetWaivers("acme/infra")
	if err != nil {
		t.Fatalf("GetWaivers: %v", err)
	}
	if len(waivers) != 0 {
		t.Errorf("expected no waivers, got %#v", waivers)
	}
}

func TestGetWaivers_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := NewClient("bad-key", srv.URL)
	if _, err := client.GetWaivers("acme/infra"); err == nil {
		t.Fatal("expected an error for an unauthorized response")
	}
}
