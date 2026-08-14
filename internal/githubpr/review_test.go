package githubpr

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/forge"
)

// reviewServer stands in for the three endpoints PostSuggestions touches.
// existingBodies seeds the review comments already on the PR.
type reviewServer struct {
	patches        map[string]string
	existingBodies []string

	gotReview map[string]any
	calls     int
}

func (s *reviewServer) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.calls++
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/files"):
			var files []map[string]string
			if r.URL.Query().Get("page") == "1" {
				for name, patch := range s.patches {
					files = append(files, map[string]string{"filename": name, "patch": patch})
				}
			}
			json.NewEncoder(w).Encode(files)

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/comments"):
			var comments []map[string]string
			if r.URL.Query().Get("page") == "1" {
				for _, b := range s.existingBodies {
					comments = append(comments, map[string]string{"body": b})
				}
			}
			json.NewEncoder(w).Encode(comments)

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/reviews"):
			json.NewDecoder(r.Body).Decode(&s.gotReview)
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]any{"id": 1})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

const twoHunkPatch = "@@ -1,3 +1,4 @@\n resource \"aws_db_instance\" \"prod\" {\n-  old = 1\n+  new = 1\n+  password = \"x\"\n }\n@@ -20,2 +21,3 @@\n context\n+added\n"

func TestPatchLineNumbers_CountsAddedAndContextButNotDeleted(t *testing.T) {
	got := forge.PatchLineNumbers(twoHunkPatch)

	// First hunk starts at new-file line 1: header(1), new(2), password(3), }(4).
	// The deleted "old = 1" must not consume a number.
	for _, want := range []int{1, 2, 3, 4} {
		if !got[want] {
			t.Errorf("line %d should be commentable; got %v", want, got)
		}
	}
	// Second hunk starts at 21: context(21), added(22).
	for _, want := range []int{21, 22} {
		if !got[want] {
			t.Errorf("line %d should be commentable; got %v", want, got)
		}
	}
	// Nothing between the hunks exists in the diff.
	for _, notWant := range []int{5, 20, 23} {
		if got[notWant] {
			t.Errorf("line %d is outside every hunk and must not be commentable", notWant)
		}
	}
}

// Context lines are not a nicety: a resource missing prevent_destroy is
// flagged on its unchanged header line, which appears only as context.
func TestPostSuggestions_CommentsOnAContextLine(t *testing.T) {
	s := &reviewServer{patches: map[string]string{"main.tf": twoHunkPatch}}
	c := testClient(t, s.start(t))

	out, err := c.PostSuggestions("summary", []ReviewComment{
		{Path: "main.tf", Line: 1, Body: "fix me", Marker: "<!-- m1 -->"},
	}, "abc123")
	if err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	if out.Posted != 1 {
		t.Fatalf("expected 1 posted, got %+v", out)
	}
	if s.gotReview["commit_id"] != "abc123" {
		t.Errorf("the review must pin to the scanned head commit, got %v", s.gotReview["commit_id"])
	}
	if s.gotReview["event"] != "COMMENT" {
		t.Errorf("event = %v — anything else leaves a pending review only its author can see", s.gotReview["event"])
	}
	comments := s.gotReview["comments"].([]any)
	first := comments[0].(map[string]any)
	if first["side"] != "RIGHT" {
		t.Errorf("side = %v, want RIGHT (the post-change file)", first["side"])
	}
	if _, hasStart := first["start_line"]; hasStart {
		t.Error("a single-line comment must not send start_line — GitHub rejects start_line == line")
	}
}

// GitHub rejects the entire review if one comment sits outside the diff, so
// filtering has to happen before anything is sent, not after a 422.
func TestPostSuggestions_DropsCommentsOutsideTheDiff(t *testing.T) {
	s := &reviewServer{patches: map[string]string{"main.tf": twoHunkPatch}}
	c := testClient(t, s.start(t))

	out, err := c.PostSuggestions("summary", []ReviewComment{
		{Path: "main.tf", Line: 3, Body: "in diff", Marker: "<!-- m1 -->"},
		{Path: "main.tf", Line: 99, Body: "not in diff", Marker: "<!-- m2 -->"},
		{Path: "untouched.tf", Line: 1, Body: "file not in PR", Marker: "<!-- m3 -->"},
	}, "")
	if err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	if out.Posted != 1 || out.OutsideDiff != 2 {
		t.Fatalf("expected 1 posted / 2 outside the diff, got %+v", out)
	}
	if len(s.gotReview["comments"].([]any)) != 1 {
		t.Error("only the in-diff comment may be sent")
	}
}

// A review can't be edited as a set the way the summary comment is upserted,
// so without this every push stacks another copy of the same suggestion.
func TestPostSuggestions_SkipsSuggestionsAlreadyOnThePR(t *testing.T) {
	s := &reviewServer{
		patches:        map[string]string{"main.tf": twoHunkPatch},
		existingBodies: []string{"some earlier comment\n<!-- m1 -->\n"},
	}
	c := testClient(t, s.start(t))

	out, err := c.PostSuggestions("summary", []ReviewComment{
		{Path: "main.tf", Line: 3, Body: "already there", Marker: "<!-- m1 -->"},
	}, "")
	if err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	if out.AlreadyThere != 1 || out.Posted != 0 {
		t.Fatalf("expected the duplicate to be skipped, got %+v", out)
	}
	if s.gotReview != nil {
		t.Error("no review should be created when every comment is a duplicate")
	}
}

// Two rules can land on the same line with the same conclusion; the author
// should see that once.
func TestPostSuggestions_DeduplicatesWithinOneReview(t *testing.T) {
	s := &reviewServer{patches: map[string]string{"main.tf": twoHunkPatch}}
	c := testClient(t, s.start(t))

	same := ReviewComment{Path: "main.tf", Line: 3, Body: "fix", Marker: "<!-- m1 -->"}
	out, err := c.PostSuggestions("summary", []ReviewComment{same, same}, "")
	if err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	if out.Posted != 1 || out.AlreadyThere != 1 {
		t.Fatalf("expected the duplicate to collapse, got %+v", out)
	}
}

func TestPostSuggestions_NoRequestsWhenThereIsNothingToPost(t *testing.T) {
	s := &reviewServer{}
	c := testClient(t, s.start(t))

	if _, err := c.PostSuggestions("summary", nil, ""); err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	if s.calls != 0 {
		t.Errorf("expected no HTTP traffic at all, got %d call(s)", s.calls)
	}
}

func TestPostSuggestions_MultiLineRangeSendsStartLine(t *testing.T) {
	s := &reviewServer{patches: map[string]string{"main.tf": twoHunkPatch}}
	c := testClient(t, s.start(t))

	if _, err := c.PostSuggestions("summary", []ReviewComment{
		{Path: "main.tf", StartLine: 2, Line: 4, Body: "range", Marker: "<!-- m -->"},
	}, ""); err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	first := s.gotReview["comments"].([]any)[0].(map[string]any)
	if first["start_line"] != float64(2) || first["line"] != float64(4) {
		t.Errorf("unexpected range: %v", first)
	}
	if first["start_side"] != "RIGHT" {
		t.Error("start_side must accompany start_line")
	}
}

// A partly-covered range is a range GitHub would reject.
func TestPostSuggestions_RejectsARangeThatLeavesTheDiff(t *testing.T) {
	s := &reviewServer{patches: map[string]string{"main.tf": twoHunkPatch}}
	c := testClient(t, s.start(t))

	out, err := c.PostSuggestions("summary", []ReviewComment{
		{Path: "main.tf", StartLine: 3, Line: 6, Body: "half outside", Marker: "<!-- m -->"},
	}, "")
	if err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	if out.OutsideDiff != 1 {
		t.Errorf("expected the range to be rejected, got %+v", out)
	}
}

// The caller logs and moves on rather than failing the scan, but it can only
// do that if the message says what GitHub actually refused.
func TestPostSuggestions_PropagatesAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/files"):
			json.NewEncoder(w).Encode([]map[string]string{{"filename": "main.tf", "patch": twoHunkPatch}})
		case r.Method == http.MethodGet:
			json.NewEncoder(w).Encode([]map[string]string{})
		default:
			w.WriteHeader(http.StatusUnprocessableEntity)
			w.Write([]byte(`{"message":"commit_id is not part of the pull request"}`))
		}
	}))
	defer srv.Close()

	c := testClient(t, srv)
	_, err := c.PostSuggestions("summary", []ReviewComment{
		{Path: "main.tf", Line: 1, Body: "x"},
	}, "stale-sha")
	if err == nil {
		t.Fatal("expected an error when GitHub rejects the review")
	}
	if !strings.Contains(err.Error(), "commit_id is not part") {
		t.Errorf("GitHub's own explanation must survive into the error, got: %v", err)
	}
}

// An empty diff means no line is commentable, so the review is never
// attempted — the scanner must not fail a PR that simply changed nothing
// it can annotate.
func TestPostSuggestions_EmptyDiffPostsNothingAndSucceeds(t *testing.T) {
	s := &reviewServer{patches: map[string]string{}}
	c := testClient(t, s.start(t))

	out, err := c.PostSuggestions("summary", []ReviewComment{
		{Path: "main.tf", Line: 1, Body: "x", Marker: "<!-- m -->"},
	}, "")
	if err != nil {
		t.Fatalf("PostSuggestions: %v", err)
	}
	if out.Posted != 0 || out.OutsideDiff != 1 {
		t.Errorf("expected the comment to be counted as outside the diff, got %+v", out)
	}
	if s.gotReview != nil {
		t.Error("no review should be created")
	}
}
