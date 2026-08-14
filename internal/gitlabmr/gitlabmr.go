// Package gitlabmr posts scan results to a GitLab merge request: the
// summary comment as an upserted note, and applicable fixes as inline
// discussions carrying GitLab's ```suggestion fence, which renders an
// "Apply suggestion" button.
//
// Same shape as githubpr, different grammar underneath. The three
// differences that matter:
//
//   - An inline comment needs a position object carrying the MR's exact
//     diff SHAs (base/start/head), fetched from the MR itself — not just a
//     path and line.
//   - The suggestion fence is range-relative: ```suggestion:-0+2 replaces
//     the commented line plus the two below it, where GitHub's plain
//     ```suggestion replaces the comment's anchored range. Rendering
//     happens in internal/report, which knows both grammars.
//   - Each discussion is its own POST; there is no batched "review" object,
//     so a partial failure leaves earlier comments posted. Markers make the
//     retry idempotent.
package gitlabmr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/forge"
)

// Client talks to one merge request.
type Client struct {
	// APIBase is GitLab's v4 API root, e.g. https://gitlab.com/api/v4 —
	// CI provides it as CI_API_V4_URL, which also makes self-hosted
	// instances work unconfigured.
	APIBase string
	// Token authenticates as PRIVATE-TOKEN. A project access token with the
	// `api` scope is the intended shape; CI_JOB_TOKEN cannot post notes.
	Token string
	// ProjectID is the numeric project ID (CI_PROJECT_ID).
	ProjectID string
	// MRIID is the merge request's project-scoped IID (CI_MERGE_REQUEST_IID).
	MRIID string

	HTTP *http.Client
}

// FromEnv builds a client from GitLab CI's predefined variables. The token
// is looked up under TFPDF_GITLAB_TOKEN first so it can be a CI/CD variable
// scoped to this tool, then GITLAB_TOKEN.
func FromEnv() (*Client, error) {
	token := os.Getenv("TFPDF_GITLAB_TOKEN")
	if token == "" {
		token = os.Getenv("GITLAB_TOKEN")
	}
	c := &Client{
		APIBase:   os.Getenv("CI_API_V4_URL"),
		Token:     token,
		ProjectID: os.Getenv("CI_PROJECT_ID"),
		MRIID:     os.Getenv("CI_MERGE_REQUEST_IID"),
	}
	switch {
	case c.APIBase == "" || c.ProjectID == "":
		return nil, fmt.Errorf("not running under GitLab CI (CI_API_V4_URL/CI_PROJECT_ID unset)")
	case c.MRIID == "":
		return nil, fmt.Errorf("no merge request in this pipeline (CI_MERGE_REQUEST_IID unset) — run the scan in a merge_request pipeline")
	case c.Token == "":
		return nil, fmt.Errorf("no token — set TFPDF_GITLAB_TOKEN (a project access token with the api scope; CI_JOB_TOKEN cannot post notes)")
	}
	return c, nil
}

func (c *Client) mrPath(suffix string) string {
	return fmt.Sprintf("%s/projects/%s/merge_requests/%s%s",
		c.APIBase, url.PathEscape(c.ProjectID), c.MRIID, suffix)
}

// UpsertComment finds the existing note containing marker and replaces its
// body, or creates a new note.
func (c *Client) UpsertComment(body, marker string) error {
	id, err := c.findNote(marker)
	if err != nil {
		return err
	}
	payload := map[string]string{"body": body}
	if id != 0 {
		return c.doJSON(http.MethodPut, c.mrPath(fmt.Sprintf("/notes/%d", id)), payload, nil)
	}
	return c.doJSON(http.MethodPost, c.mrPath("/notes"), payload, nil)
}

func (c *Client) findNote(marker string) (int, error) {
	for page := 1; page <= 10; page++ {
		var notes []struct {
			ID   int    `json:"id"`
			Body string `json:"body"`
		}
		if err := c.getJSON(c.mrPath(fmt.Sprintf("/notes?per_page=100&page=%d", page)), &notes); err != nil {
			return 0, err
		}
		for _, n := range notes {
			if strings.Contains(n.Body, marker) {
				return n.ID, nil
			}
		}
		if len(notes) < 100 {
			break
		}
	}
	return 0, nil
}

// PostSuggestions attaches the comments as inline discussions.
//
// headSHA, when non-empty, is compared against the MR's current head: if the
// branch moved since the scan, nothing is posted rather than pinning
// suggestions to lines that no longer say what the scan saw.
func (c *Client) PostSuggestions(summary string, comments []forge.InlineComment, headSHA string) (forge.SuggestionOutcome, error) {
	var out forge.SuggestionOutcome
	if len(comments) == 0 {
		return out, nil
	}

	refs, err := c.diffRefs()
	if err != nil {
		return out, err
	}
	if headSHA != "" && refs.Head != headSHA {
		return out, fmt.Errorf("merge request head moved (scanned %.8s, MR is at %.8s) — suggestions skipped, the next pipeline will post them", headSHA, refs.Head)
	}

	diffLines, err := c.commentableLines()
	if err != nil {
		return out, err
	}
	existing, err := c.existingNoteBodies()
	if err != nil {
		return out, err
	}

	posted := 0
	inBatch := map[string]bool{}
	for _, cm := range comments {
		if cm.Marker != "" && (strings.Contains(existing, cm.Marker) || inBatch[cm.Marker]) {
			out.AlreadyThere++
			continue
		}
		inBatch[cm.Marker] = true
		if !forge.LinesInDiff(diffLines, cm) {
			out.OutsideDiff++
			continue
		}

		// The suggestion fence in the body is range-relative to its anchor,
		// so a multi-line fix anchors at its first line; the fence's +N
		// covers the rest.
		anchor := cm.StartLine
		if anchor <= 0 {
			anchor = cm.Line
		}
		payload := map[string]any{
			"body": cm.Body,
			"position": map[string]any{
				"position_type": "text",
				"base_sha":      refs.Base,
				"start_sha":     refs.Start,
				"head_sha":      refs.Head,
				"new_path":      cm.Path,
				"old_path":      cm.Path,
				"new_line":      anchor,
			},
		}
		if err := c.doJSON(http.MethodPost, c.mrPath("/discussions"), payload, nil); err != nil {
			// Each discussion is its own request; report what landed before
			// the failure so the numbers stay honest.
			out.Posted = posted
			return out, fmt.Errorf("after posting %d suggestion(s): %w", posted, err)
		}
		posted++
	}
	out.Posted = posted

	// The batch summary goes as a plain note, once, only when something was
	// posted — GitLab has no review object to carry it.
	if posted > 0 && summary != "" {
		if err := c.doJSON(http.MethodPost, c.mrPath("/notes"), map[string]string{"body": summary}, nil); err != nil {
			return out, err
		}
	}
	return out, nil
}

type refs struct {
	Base  string
	Start string
	Head  string
}

func (c *Client) diffRefs() (refs, error) {
	var mr struct {
		DiffRefs struct {
			BaseSHA  string `json:"base_sha"`
			StartSHA string `json:"start_sha"`
			HeadSHA  string `json:"head_sha"`
		} `json:"diff_refs"`
	}
	if err := c.getJSON(c.mrPath(""), &mr); err != nil {
		return refs{}, err
	}
	if mr.DiffRefs.HeadSHA == "" {
		return refs{}, fmt.Errorf("merge request has no diff_refs yet")
	}
	return refs{Base: mr.DiffRefs.BaseSHA, Start: mr.DiffRefs.StartSHA, Head: mr.DiffRefs.HeadSHA}, nil
}

func (c *Client) commentableLines() (map[string]map[int]bool, error) {
	out := map[string]map[int]bool{}
	for page := 1; page <= 10; page++ {
		var files []struct {
			NewPath string `json:"new_path"`
			Diff    string `json:"diff"`
		}
		if err := c.getJSON(c.mrPath(fmt.Sprintf("/diffs?per_page=100&page=%d", page)), &files); err != nil {
			return nil, err
		}
		for _, f := range files {
			out[f.NewPath] = forge.PatchLineNumbers(f.Diff)
		}
		if len(files) < 100 {
			break
		}
	}
	return out, nil
}

// existingNoteBodies concatenates every note on the MR — discussion notes
// included — for marker searching.
func (c *Client) existingNoteBodies() (string, error) {
	var b strings.Builder
	for page := 1; page <= 10; page++ {
		var notes []struct {
			Body string `json:"body"`
		}
		if err := c.getJSON(c.mrPath(fmt.Sprintf("/notes?per_page=100&page=%d", page)), &notes); err != nil {
			return "", err
		}
		for _, n := range notes {
			b.WriteString(n.Body)
			b.WriteByte('\n')
		}
		if len(notes) < 100 {
			break
		}
	}
	return b.String(), nil
}

func (c *Client) getJSON(url string, into any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", c.Token)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s failed: %s: %s", url, resp.Status, string(b))
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

func (c *Client) doJSON(method, url string, payload any, into any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s failed: %s: %s", method, url, resp.Status, string(b))
	}
	if into != nil {
		return json.NewDecoder(resp.Body).Decode(into)
	}
	return nil
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
