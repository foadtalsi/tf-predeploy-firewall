// Package licensing talks to the optional TF Pre-Deploy Firewall control
// plane (billing/usage tracking for paid plans). It is entirely opt-in: if
// no API key is configured, nothing in this package is invoked and the
// scanner behaves exactly like the open-source, unlicensed tool it always
// has been. This keeps the core scan engine itself license-free — only the
// usage/quota check talks to a paid service.
package licensing

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const DefaultAPIBase = "https://api.tfpredeployfirewall.com"

type Client struct {
	APIKey  string
	APIBase string
	HTTP    *http.Client
}

func NewClient(apiKey, apiBase string) *Client {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	return &Client{
		APIKey:  apiKey,
		APIBase: apiBase,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// ScanResult is what the CLI reports about a completed scan, used both for
// usage metering and for quota enforcement decisions.
type ScanResult struct {
	RepoFullName string
	FindingCount int
	Blocked      bool
}

type recordScanRequest struct {
	RepoFullName string `json:"repo_full_name"`
	FindingCount int    `json:"finding_count"`
	Blocked      bool   `json:"blocked"`
}

type recordScanResponse struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// RecordScan reports a completed scan to the control plane and returns
// whether the org's plan allows it. Network or server errors are returned
// as-is; callers should decide for themselves whether a licensing-service
// outage should block the scan (fail closed) or just log a warning and
// continue (fail open) — this package takes no position on that.
func (c *Client) RecordScan(result ScanResult) (allowed bool, reason string, err error) {
	body, err := json.Marshal(recordScanRequest{
		RepoFullName: result.RepoFullName,
		FindingCount: result.FindingCount,
		Blocked:      result.Blocked,
	})
	if err != nil {
		return false, "", fmt.Errorf("encoding usage report: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.APIBase+"/v1/usage/scan", bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("building usage request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return false, "", fmt.Errorf("reaching licensing service: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("reading licensing response: %w", err)
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return false, "", fmt.Errorf("invalid or revoked API key")
	}
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("licensing service returned %s: %s", resp.Status, string(respBody))
	}

	var out recordScanResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return false, "", fmt.Errorf("parsing licensing response: %w", err)
	}
	return out.Allowed, out.Reason, nil
}
