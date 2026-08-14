package gitlabmr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/forge"
)

const mrPatch = "@@ -1,3 +1,4 @@\n resource \"aws_db_instance\" \"prod\" {\n-  old = 1\n+  new = 1\n+  password = \"x\"\n }\n"

// glServer simulates the four MR endpoints the client touches.
type glServer struct {
	notes       []map[string]any
	diffRefs    map[string]string
	gotCreated  []map[string]any // POSTed notes bodies
	discussions []map[string]any // POSTed discussions
	updatedNote map[string]any
}

func (s *glServer) start(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/merge_requests/7"):
			json.NewEncoder(w).Encode(map[string]any{"diff_refs": s.diffRefs})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/diffs"):
			out := []map[string]string{}
			if r.URL.Query().Get("page") == "1" {
				out = append(out, map[string]string{"new_path": "main.tf", "diff": mrPatch})
			}
			json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/notes"):
			out := []map[string]any{}
			if r.URL.Query().Get("page") == "1" {
				out = s.notes
			}
			json.NewEncoder(w).Encode(out)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/notes/"):
			json.NewDecoder(r.Body).Decode(&s.updatedNote)
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/notes"):
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			s.gotCreated = append(s.gotCreated, body)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"id": 2})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/discussions"):
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			s.discussions = append(s.discussions, body)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"id": "d1"})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return &Client{APIBase: srv.URL, Token: "tok", ProjectID: "42", MRIID: "7"}
}

func refsOK() map[string]string {
	return map[string]string{"base_sha": "b1", "start_sha": "s1", "head_sha": "h1"}
}

func TestUpsertComment_CreatesThenUpdates(t *testing.T) {
	s := &glServer{}
	c := s.start(t)

	if err := c.UpsertComment("first <!-- m -->", "<!-- m -->"); err != nil {
		t.Fatal(err)
	}
	if len(s.gotCreated) != 1 || s.gotCreated[0]["body"] != "first <!-- m -->" {
		t.Fatalf("expected one created note, got %v", s.gotCreated)
	}

	s.notes = []map[string]any{{"id": 5, "body": "first <!-- m -->"}}
	if err := c.UpsertComment("second <!-- m -->", "<!-- m -->"); err != nil {
		t.Fatal(err)
	}
	if s.updatedNote == nil || s.updatedNote["body"] != "second <!-- m -->" {
		t.Fatalf("expected the existing note to be updated, got %v", s.updatedNote)
	}
}

// The position object is what makes an inline comment inline; the SHAs come
// from the MR's own diff_refs, and the anchor is the fix's FIRST line since
// GitLab's suggestion fence extends downward from its anchor.
func TestPostSuggestions_AnchorsAtStartLineWithDiffRefs(t *testing.T) {
	s := &glServer{diffRefs: refsOK()}
	c := s.start(t)

	out, err := c.PostSuggestions("summary", []forge.InlineComment{
		{Path: "main.tf", StartLine: 2, Line: 4, Body: "```suggestion:-0+2\nfix\n```", Marker: "<!-- m -->"},
	}, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Posted != 1 {
		t.Fatalf("outcome %+v", out)
	}
	pos := s.discussions[0]["position"].(map[string]any)
	if pos["new_line"] != float64(2) {
		t.Errorf("anchor = %v, want the range's first line", pos["new_line"])
	}
	for k, want := range map[string]string{"base_sha": "b1", "start_sha": "s1", "head_sha": "h1", "new_path": "main.tf"} {
		if pos[k] != want {
			t.Errorf("position.%s = %v, want %s", k, pos[k], want)
		}
	}
	// The batch summary is posted as a plain note.
	if len(s.gotCreated) != 1 || !strings.Contains(s.gotCreated[0]["body"].(string), "summary") {
		t.Error("expected the summary note after posting suggestions")
	}
}

// If the branch moved since the scan, the lines the fixes point at may no
// longer say what the scan saw. Refusing wholesale beats posting stale
// suggestions someone applies with one click.
func TestPostSuggestions_RefusesWhenTheMRHeadMoved(t *testing.T) {
	s := &glServer{diffRefs: refsOK()}
	c := s.start(t)

	_, err := c.PostSuggestions("s", []forge.InlineComment{
		{Path: "main.tf", Line: 2, Body: "b", Marker: "<!-- m -->"},
	}, "older-sha")
	if err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("expected a branch-moved refusal, got %v", err)
	}
	if len(s.discussions) != 0 {
		t.Error("nothing may be posted against a moved head")
	}
}

func TestPostSuggestions_FiltersOutsideDiffAndDuplicates(t *testing.T) {
	s := &glServer{
		diffRefs: refsOK(),
		notes:    []map[string]any{{"id": 1, "body": "earlier\n<!-- dup -->"}},
	}
	c := s.start(t)

	out, err := c.PostSuggestions("s", []forge.InlineComment{
		{Path: "main.tf", Line: 3, Body: "b", Marker: "<!-- dup -->"},  // already there
		{Path: "main.tf", Line: 99, Body: "b", Marker: "<!-- new -->"}, // outside diff
		{Path: "main.tf", Line: 3, Body: "b", Marker: "<!-- ok -->"},   // posts
	}, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if out.Posted != 1 || out.AlreadyThere != 1 || out.OutsideDiff != 1 {
		t.Fatalf("outcome %+v", out)
	}
}

func TestFromEnv_ExplainsWhatIsMissing(t *testing.T) {
	t.Setenv("CI_API_V4_URL", "https://gitlab.example.com/api/v4")
	t.Setenv("CI_PROJECT_ID", "42")
	t.Setenv("CI_MERGE_REQUEST_IID", "7")
	t.Setenv("TFPDF_GITLAB_TOKEN", "")
	t.Setenv("GITLAB_TOKEN", "")

	_, err := FromEnv()
	if err == nil || !strings.Contains(err.Error(), "CI_JOB_TOKEN cannot post notes") {
		t.Errorf("the no-token error must explain why CI_JOB_TOKEN isn't enough, got: %v", err)
	}

	t.Setenv("TFPDF_GITLAB_TOKEN", "tok")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Token != "tok" {
		t.Errorf("token = %q", c.Token)
	}
}
