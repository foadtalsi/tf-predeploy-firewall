package githubpr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	return &Client{
		Token:   "test-token",
		Owner:   "owner",
		Repo:    "repo",
		PRNum:   42,
		APIBase: server.URL,
	}
}

func TestUpsertComment_CreatesWhenNoneExists(t *testing.T) {
	var posted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/comments"):
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]any{}) // no existing comments
		case r.Method == http.MethodPost:
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			posted = body["body"]
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := testClient(t, srv)
	if err := c.UpsertComment("hello <!-- marker -->", "<!-- marker -->"); err != nil {
		t.Fatalf("UpsertComment: %v", err)
	}
	if posted != "hello <!-- marker -->" {
		t.Errorf("unexpected posted body: %q", posted)
	}
}

func TestUpsertComment_UpdatesExisting(t *testing.T) {
	var patched string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": 99, "body": "old body <!-- marker -->"},
			})
		case r.Method == http.MethodPatch:
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			patched = body["body"]
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"id": 99})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := testClient(t, srv)
	if err := c.UpsertComment("new body <!-- marker -->", "<!-- marker -->"); err != nil {
		t.Fatalf("UpsertComment: %v", err)
	}
	if patched != "new body <!-- marker -->" {
		t.Errorf("unexpected patched body: %q", patched)
	}
}

func TestUpsertComment_AuthHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode([]map[string]any{})
		} else {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		}
	}))
	defer srv.Close()

	c := testClient(t, srv)
	c.UpsertComment("body", "marker")
	if gotAuth != "Bearer test-token" {
		t.Errorf("expected Bearer auth, got %q", gotAuth)
	}
}
