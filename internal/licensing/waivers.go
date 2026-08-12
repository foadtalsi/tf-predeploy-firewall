package licensing

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
)

// Waiver is an admin's decision (Starter+, via the dashboard) to accept a
// specific finding rather than have it block merges — matched by
// category+resource+file within one repo, not by line number (line shifts
// when unrelated code above it changes; requiring an exact line match
// would make a waiver go stale on the next unrelated edit).
type Waiver struct {
	Category      string `json:"category"`
	Resource      string `json:"resource"`
	FilePath      string `json:"file"`
	Justification string `json:"justification"`
}

// GetWaivers fetches every active (non-expired) waiver configured for
// repoFullName. Returns an empty slice (not an error) when none exist —
// the normal state for a repo nobody has waived anything on yet.
func (c *Client) GetWaivers(repoFullName string) ([]Waiver, error) {
	url := c.APIBase + "/v1/waivers?repo=" + neturl.QueryEscape(repoFullName)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building waivers request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reaching licensing service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("invalid or revoked API key")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("licensing service returned %s", resp.Status)
	}

	var waivers []Waiver
	if err := json.NewDecoder(resp.Body).Decode(&waivers); err != nil {
		return nil, fmt.Errorf("parsing waivers response: %w", err)
	}
	return waivers, nil
}
