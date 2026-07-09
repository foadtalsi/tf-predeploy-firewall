// Command scanner is the TF Pre-Deploy Firewall CLI: it scans the .tf files
// changed between two git refs, reports risk findings, and optionally
// posts/updates a PR comment and gates the exit code on a severity threshold.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/githubpr"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/rules"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
	"gopkg.in/yaml.v3"
)

type config struct {
	BlockThreshold report.Severity   `yaml:"block_threshold"`
	IgnoreRules    []report.Category `yaml:"ignore_rules"`
}

func main() {
	repoDir := flag.String("repo-dir", ".", "path to the git repository to scan")
	baseRef := flag.String("base-ref", envOr("GITHUB_BASE_REF", "origin/main"), "git ref to diff against (PR base)")
	headRef := flag.String("head-ref", "HEAD", "git ref containing the proposed changes")
	configPath := flag.String("config", envOr("SCANNER_CONFIG", "config/default.yml"), "path to YAML config")
	postComment := flag.Bool("post-comment", os.Getenv("GITHUB_TOKEN") != "", "post/update a PR comment with the results")
	sarifOut := flag.String("sarif-output", "", "write SARIF 2.1.0 JSON to this file (for GitHub Code Scanning)")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}

	aws, err := schema.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}

	changed, err := diff.ChangedTerraformFiles(*repoDir, *baseRef, *headRef)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}

	findings, err := rules.Run(changed, aws, rules.DefaultRules(), rules.RunOptions{
		GlobalIgnore: cfg.IgnoreRules,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}

	blocked := blockedBy(findings, cfg.BlockThreshold)
	body := report.RenderMarkdown(findings, cfg.BlockThreshold, blocked)
	fmt.Println(body)

	if *postComment {
		if err := postToPR(body); err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: failed to post PR comment: %v\n", err)
		}
	}

	if *sarifOut != "" {
		sarifBytes, err := report.RenderSARIF(findings)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: failed to render SARIF: %v\n", err)
		} else if err := os.WriteFile(*sarifOut, sarifBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: failed to write SARIF file: %v\n", err)
		}
	}

	if blocked {
		os.Exit(1)
	}
}

func blockedBy(findings []report.Finding, threshold report.Severity) bool {
	for _, f := range findings {
		if f.Severity.AtLeast(threshold) {
			return true
		}
	}
	return false
}

func loadConfig(path string) (config, error) {
	cfg := config{BlockThreshold: report.SeverityHigh}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil // fall back to defaults
		}
		return cfg, fmt.Errorf("reading config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parsing config %s: %w", path, err)
	}
	if cfg.BlockThreshold == "" {
		cfg.BlockThreshold = report.SeverityHigh
	}
	if env := os.Getenv("SCANNER_BLOCK_THRESHOLD"); env != "" {
		cfg.BlockThreshold = report.Severity(env)
	}
	return cfg, nil
}

// postToPR reads GitHub Actions context (GITHUB_TOKEN, GITHUB_REPOSITORY,
// GITHUB_EVENT_PATH) to upsert the report as a PR comment.
func postToPR(body string) error {
	token := os.Getenv("GITHUB_TOKEN")
	repoFull := os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repoFull == "" {
		return fmt.Errorf("GITHUB_TOKEN/GITHUB_REPOSITORY not set; skipping comment")
	}
	parts := strings.SplitN(repoFull, "/", 2)
	if len(parts) != 2 {
		return fmt.Errorf("unexpected GITHUB_REPOSITORY format: %s", repoFull)
	}

	prNumber, err := prNumberFromEvent()
	if err != nil {
		return err
	}

	client := &githubpr.Client{Token: token, Owner: parts[0], Repo: parts[1], PRNum: prNumber}
	return client.UpsertComment(body, report.Marker)
}

func prNumberFromEvent() (int, error) {
	if v := os.Getenv("PR_NUMBER"); v != "" {
		return strconv.Atoi(v)
	}
	eventPath := os.Getenv("GITHUB_EVENT_PATH")
	if eventPath == "" {
		return 0, fmt.Errorf("GITHUB_EVENT_PATH not set and PR_NUMBER not provided")
	}
	data, err := os.ReadFile(eventPath)
	if err != nil {
		return 0, fmt.Errorf("reading GITHUB_EVENT_PATH: %w", err)
	}
	var event struct {
		PullRequest struct {
			Number int `json:"number"`
		} `json:"pull_request"`
	}
	if err := json.Unmarshal(data, &event); err != nil {
		return 0, fmt.Errorf("parsing event payload: %w", err)
	}
	if event.PullRequest.Number == 0 {
		return 0, fmt.Errorf("event payload has no pull_request.number (not a pull_request event?)")
	}
	return event.PullRequest.Number, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
