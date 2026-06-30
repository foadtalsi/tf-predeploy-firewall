// Package githubpr posts (or updates) the scan report as a PR comment via
// the plain GitHub REST API — no SDK dependency needed for this single call.
package githubpr

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type Client struct {
	Token   string
	Owner   string
	Repo    string
	PRNum   int
	APIBase string // override for tests; defaults to https://api.github.com
}

func (c *Client) apiBase() string {
	if c.APIBase != "" {
		return c.APIBase
	}
	return "https://api.github.com"
}

// UpsertComment finds an existing comment containing marker on the PR and
// replaces its body, or creates a new comment if none exists.
func (c *Client) UpsertComment(body, marker string) error {
	existingID, err := c.findExistingComment(marker)
	if err != nil {
		return err
	}
	if existingID != 0 {
		return c.patchComment(existingID, body)
	}
	return c.postComment(body)
}

func (c *Client) findExistingComment(marker string) (int, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments?per_page=100", c.apiBase(), c.Owner, c.Repo, c.PRNum)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	c.setHeaders(req)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("list comments failed: %s: %s", resp.Status, string(b))
	}

	var comments []struct {
		ID   int    `json:"id"`
		Body string `json:"body"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&comments); err != nil {
		return 0, err
	}
	for _, cm := range comments {
		if strings.Contains(cm.Body, marker) {
			return cm.ID, nil
		}
	}
	return 0, nil
}

func (c *Client) postComment(body string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", c.apiBase(), c.Owner, c.Repo, c.PRNum)
	return c.doJSON(http.MethodPost, url, body)
}

func (c *Client) patchComment(id int, body string) error {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/comments/%d", c.apiBase(), c.Owner, c.Repo, id)
	return c.doJSON(http.MethodPatch, url, body)
}

func (c *Client) doJSON(method, url, body string) error {
	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s failed: %s: %s", method, url, resp.Status, string(b))
	}
	return nil
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
}
