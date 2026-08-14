package githubpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/forge"
)

// ReviewComment and ReviewOutcome are the forge-neutral types, aliased so
// existing callers and tests keep reading naturally.
type ReviewComment = forge.InlineComment

type ReviewOutcome = forge.SuggestionOutcome

// PostSuggestions attaches comments to the PR as a single review.
//
// Two GitHub constraints shape this. First, a review comment can only land
// on a line that appears in the diff — anything else makes the API reject
// the entire review, not just the offending comment — so the diff is fetched
// and comments outside it are filtered out here rather than discovered as a
// 422. Second, a review cannot be edited as a unit the way the summary
// comment is upserted; re-running would stack a fresh copy of every
// suggestion onto the PR. Both are handled before anything is posted.
//
// commitSHA should be the PR head this scan actually ran against. Passing it
// means that if the branch moved in the meantime, GitHub rejects the review
// instead of pinning suggestions to lines that have since changed.
//
// Returns with nothing posted, and no error, when every comment was filtered
// out — the common case on a re-run where nothing changed.
func (c *Client) PostSuggestions(summary string, comments []ReviewComment, commitSHA string) (ReviewOutcome, error) {
	var out ReviewOutcome
	if len(comments) == 0 {
		return out, nil
	}

	diffLines, err := c.commentableLines()
	if err != nil {
		return out, err
	}
	existing, err := c.existingReviewComments()
	if err != nil {
		return out, err
	}

	type apiComment struct {
		Path      string `json:"path"`
		Line      int    `json:"line"`
		StartLine int    `json:"start_line,omitempty"`
		Side      string `json:"side"`
		StartSide string `json:"start_side,omitempty"`
		Body      string `json:"body"`
	}

	var payload []apiComment
	inBatch := map[string]bool{}
	for _, cm := range comments {
		// Already on the PR from an earlier push, or already in this batch —
		// two rules can reach the same conclusion about the same line.
		if cm.Marker != "" && (strings.Contains(existing, cm.Marker) || inBatch[cm.Marker]) {
			out.AlreadyThere++
			continue
		}
		inBatch[cm.Marker] = true
		if !forge.LinesInDiff(diffLines, cm) {
			out.OutsideDiff++
			continue
		}
		ac := apiComment{Path: cm.Path, Line: cm.Line, Body: cm.Body, Side: "RIGHT"}
		if cm.StartLine > 0 && cm.StartLine < cm.Line {
			ac.StartLine = cm.StartLine
			ac.StartSide = "RIGHT"
		}
		payload = append(payload, ac)
	}

	if len(payload) == 0 {
		return out, nil
	}

	body := map[string]any{
		"event":    "COMMENT",
		"body":     summary,
		"comments": payload,
	}
	if commitSHA != "" {
		body["commit_id"] = commitSHA
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return out, err
	}

	url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/reviews", c.apiBase(), c.Owner, c.Repo, c.PRNum)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return out, err
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return out, fmt.Errorf("creating review failed: %s: %s", resp.Status, string(b))
	}

	out.Posted = len(payload)
	return out, nil
}

// commentableLines maps each changed file to the set of line numbers, in the
// post-change file, that GitHub will accept a review comment on. Both added
// and context lines qualify; only the deleted ones don't, since they have no
// position in the new file.
//
// Context lines mattering is not a detail: a resource missing
// prevent_destroy is usually flagged on its unchanged `resource "…" {`
// header, which appears in the diff only as context.
func (c *Client) commentableLines() (map[string]map[int]bool, error) {
	out := map[string]map[int]bool{}

	for page := 1; page <= 10; page++ { // 300 changed files is far past the point of usefulness
		url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/files?per_page=100&page=%d",
			c.apiBase(), c.Owner, c.Repo, c.PRNum, page)
		var files []struct {
			Filename string `json:"filename"`
			Patch    string `json:"patch"`
		}
		if err := c.getJSON(url, &files); err != nil {
			return nil, err
		}
		for _, f := range files {
			out[f.Filename] = forge.PatchLineNumbers(f.Patch)
		}
		if len(files) < 100 {
			break
		}
	}
	return out, nil
}

// existingReviewComments returns every inline review comment body already on
// the PR, concatenated — callers only ever substring-search it for markers,
// so keeping them apart would buy nothing.
func (c *Client) existingReviewComments() (string, error) {
	var b strings.Builder

	for page := 1; page <= 10; page++ {
		url := fmt.Sprintf("%s/repos/%s/%s/pulls/%d/comments?per_page=100&page=%d",
			c.apiBase(), c.Owner, c.Repo, c.PRNum, page)
		var comments []struct {
			Body string `json:"body"`
		}
		if err := c.getJSON(url, &comments); err != nil {
			return "", err
		}
		for _, cm := range comments {
			b.WriteString(cm.Body)
			b.WriteByte('\n')
		}
		if len(comments) < 100 {
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
	c.setHeaders(req)

	resp, err := http.DefaultClient.Do(req)
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
