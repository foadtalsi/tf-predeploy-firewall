package licensing

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
)

// Policy is a Growth-tier org-wide override of the scanner's defaults,
// managed centrally via the control plane rather than scattered across
// each repo's local config.yml. A nil/empty field means "no override for
// this setting" — the caller should keep whatever the local config said.
type Policy struct {
	BlockThreshold           *string  `json:"block_threshold,omitempty"`
	IgnoreRules              []string `json:"ignore_rules,omitempty"`
	PlanBlastRadiusThreshold *int     `json:"plan_blast_radius_threshold,omitempty"`
	CostImpactThresholdUSD   *float64 `json:"cost_impact_threshold_usd,omitempty"`
	// CustomRulesYAML is a full custom-rules document (same format as the
	// `custom_rules:` section of config/default.yml — see
	// internal/customrules), managed centrally so an org doesn't have to
	// commit rule changes to every repo separately. When set, it replaces
	// (not merges with) any custom_rules in the repo's local config —
	// same "central policy wins" precedent as IgnoreRules below.
	CustomRulesYAML *string `json:"custom_rules_yaml,omitempty"`
	// RequireSecondReviewerUsers/Teams: same meaning as the local config
	// fields of the same name — requests review from these GitHub
	// usernames/team slugs whenever a critical finding is present.
	RequireSecondReviewerUsers []string `json:"require_second_reviewer_users,omitempty"`
	RequireSecondReviewerTeams []string `json:"require_second_reviewer_teams,omitempty"`
}

// GetPolicy fetches the org's centrally-managed policy, if any, merged with
// repoFullName's own override (if the org has configured one for this
// specific repo — a repo override wins per-field over the org-wide
// policy). Pass "" to get the org-wide policy unmerged. Returns a nil
// Policy (not an error) when neither exists — that's the normal state for
// Starter-tier orgs and any Growth-tier org that hasn't configured custom
// rules yet.
func (c *Client) GetPolicy(repoFullName string) (*Policy, error) {
	url := c.APIBase + "/v1/policy"
	if repoFullName != "" {
		url += "?repo=" + neturl.QueryEscape(repoFullName)
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building policy request: %w", err)
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

	var p Policy
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil, fmt.Errorf("parsing policy response: %w", err)
	}
	if p.BlockThreshold == nil && p.IgnoreRules == nil && p.PlanBlastRadiusThreshold == nil && p.CostImpactThresholdUSD == nil &&
		p.CustomRulesYAML == nil && p.RequireSecondReviewerUsers == nil && p.RequireSecondReviewerTeams == nil {
		return nil, nil
	}
	return &p, nil
}
