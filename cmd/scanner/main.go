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

	"github.com/foadtalsi/tf-predeploy-firewall/internal/customrules"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/githubpr"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/ignore"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/licensing"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/rules"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/terragrunt"
	"gopkg.in/yaml.v3"
)

type config struct {
	BlockThreshold           report.Severity   `yaml:"block_threshold"`
	IgnoreRules              []report.Category `yaml:"ignore_rules"`
	PlanBlastRadiusThreshold int               `yaml:"plan_blast_radius_threshold"`
	CostImpactThresholdUSD   float64           `yaml:"cost_impact_threshold_usd"`

	// IgnorePaths suppresses findings under an entire file/directory glob
	// (supports "**"), optionally scoped to specific categories — the
	// large-scale companion to an inline `# tf-firewall-ignore:` comment
	// (one line) and ignore_rules (one category everywhere): "don't scan
	// legacy/** at all" without littering every file in that tree.
	IgnorePaths []ignorePathConfig `yaml:"ignore_paths"`

	// RequireSecondReviewerUsers/Teams: GitHub usernames/team slugs
	// requested as reviewers whenever a critical-severity finding is
	// present. This only requests the review — actually BLOCKING the
	// merge on it requires the repo's branch protection to have "required
	// reviewers" turned on, which is a one-time GitHub setting this tool
	// has no API access to configure itself.
	RequireSecondReviewerUsers []string `yaml:"require_second_reviewer_users"`
	RequireSecondReviewerTeams []string `yaml:"require_second_reviewer_teams"`

	// CustomRulesYAMLOverride is never read from the local YAML file (no
	// yaml tag) — it's only ever populated by applyOrgPolicy from the
	// control plane's centrally-managed policy. When set, it replaces the
	// local config's custom_rules entirely, same "central policy wins"
	// precedent as IgnoreRules.
	CustomRulesYAMLOverride string
}

// ignorePathConfig is one ignore_paths entry from config.yml:
//
//	ignore_paths:
//	  - path: "legacy/**/*.tf"
//	    categories: ["missing_lifecycle"]   # optional; omitted = every category
//	  - path: "sandbox/**"
type ignorePathConfig struct {
	Path       string            `yaml:"path"`
	Categories []report.Category `yaml:"categories"`
}

func (cfg config) ignorePathRules() []ignore.PathRule {
	rules := make([]ignore.PathRule, len(cfg.IgnorePaths))
	for i, p := range cfg.IgnorePaths {
		rules[i] = ignore.PathRule{Pattern: p.Path, Categories: p.Categories}
	}
	return rules
}

func main() {
	repoDir := flag.String("repo-dir", ".", "path to the git repository to scan")
	baseRef := flag.String("base-ref", envOr("GITHUB_BASE_REF", "origin/main"), "git ref to diff against (PR base)")
	headRef := flag.String("head-ref", "HEAD", "git ref containing the proposed changes")
	fullRepoScan := flag.Bool("full-repo-scan", false, "scan every .tf file in repo-dir instead of just the PR diff — for a scheduled drift audit of already-merged code (e.g. cron), not a PR check. ForceNew-change detection naturally finds nothing (there's no diff), but unknown-attribute, tutorial-pattern, and missing-lifecycle findings run at full strength against current content.")
	configPath := flag.String("config", envOr("SCANNER_CONFIG", "config/default.yml"), "path to YAML config")
	postComment := flag.Bool("post-comment", os.Getenv("GITHUB_TOKEN") != "", "post/update a PR comment with the results")
	sarifOut := flag.String("sarif-output", "", "write SARIF 2.1.0 JSON to this file (for GitHub Code Scanning)")
	planJSONPath := flag.String("plan-json", "", "path to `terraform show -json <planfile>` output (phase 2: adds confirmed-replace, drift, and blast-radius findings). Optional — this tool never runs terraform or touches cloud credentials itself.")
	licenseKey := flag.String("license-key", envOr("TFPDF_LICENSE_KEY", ""), "paid-plan API key. Entirely optional — leave unset to run the scanner exactly as the free, open-source tool it has always been. When set, each scan is reported to the billing/usage service for quota enforcement.")
	licenseAPIBase := flag.String("license-api-base", envOr("TFPDF_LICENSE_API_BASE", licensing.DefaultAPIBase), "control-plane API base URL, override for self-hosted/staging deployments")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}

	if *licenseKey != "" {
		applyOrgPolicy(&cfg, *licenseKey, *licenseAPIBase)
	}

	aws, err := schema.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}

	var changed []diff.ChangedFile
	if *fullRepoScan {
		changed, err = diff.AllTerraformFiles(*repoDir)
	} else {
		changed, err = diff.ChangedTerraformFiles(*repoDir, *baseRef, *headRef)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}

	ruleset := rules.DefaultRules()
	var customRuleSet *customrules.Config
	if cfg.CustomRulesYAMLOverride != "" {
		customRuleSet, err = customrules.Load([]byte(cfg.CustomRulesYAMLOverride))
		if err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: custom rules from org policy: %v\n", err)
			os.Exit(2)
		}
	} else {
		customRuleSet, err = loadCustomRules(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
			os.Exit(2)
		}
	}
	if customRuleSet != nil {
		ruleset = append(ruleset, customRuleSet.AsEngineRule())
	}

	result, err := rules.Run(changed, aws, ruleset, rules.RunOptions{
		GlobalIgnore: cfg.IgnoreRules,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}
	findings := result.Findings

	if *planJSONPath != "" {
		pf, err := planjson.Load(*planJSONPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
			os.Exit(2)
		}
		planFindings := rules.RunPlanRules(*planJSONPath, pf, result.ChangedAttrs, aws, rules.PlanRuleConfig{
			BlastRadiusThreshold:   cfg.PlanBlastRadiusThreshold,
			CostImpactThresholdUSD: cfg.CostImpactThresholdUSD,
			GlobalIgnore:           cfg.IgnoreRules,
		})
		// A confirmed replace from the real plan supersedes phase 1's
		// ForceNew heuristic for the same resource — drop the guess once
		// we have certainty, instead of reporting the same problem twice.
		findings = rules.DeduplicateForceNewAgainstPlan(findings, planFindings)
		findings = append(findings, planFindings...)
	}

	var terragruntChanged []diff.ChangedFile
	if *fullRepoScan {
		terragruntChanged, err = diff.AllTerragruntFiles(*repoDir)
	} else {
		terragruntChanged, err = diff.ChangedTerragruntFiles(*repoDir, *baseRef, *headRef)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		os.Exit(2)
	}
	var terragruntFindings []report.Finding
	for _, f := range terragruntChanged {
		found, err := terragrunt.ScanFile(f.Path, f.HeadContent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
			continue
		}
		terragruntFindings = append(terragruntFindings, found...)
	}
	findings = append(findings, ignore.Apply(terragruntFindings, nil, cfg.IgnoreRules)...)

	findings = ignore.ApplyPathRules(findings, cfg.ignorePathRules())

	if *licenseKey != "" {
		findings = applyWaivers(findings, *licenseKey, *licenseAPIBase)
	}

	blocked := blockedBy(findings, cfg.BlockThreshold)

	if *licenseKey != "" {
		if quotaExceeded := reportUsage(*licenseKey, *licenseAPIBase, findings, blocked); quotaExceeded {
			os.Exit(3)
		}
	}

	body := report.RenderMarkdown(findings, cfg.BlockThreshold, blocked)
	fmt.Println(body)

	if *postComment {
		if err := postToPR(body); err != nil {
			fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: failed to post PR comment: %v\n", err)
		}
		requestSecondReviewerIfCritical(findings, cfg)
	}

	if *sarifOut != "" {
		// Waived findings are excluded from SARIF entirely — GitHub's
		// Security tab is for open issues, and an accepted finding isn't
		// one; it stays visible in the PR comment's waived section instead.
		sarifFindings := make([]report.Finding, 0, len(findings))
		for _, f := range findings {
			if !f.Waived {
				sarifFindings = append(sarifFindings, f)
			}
		}
		sarifBytes, err := report.RenderSARIF(sarifFindings)
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

// reportUsage sends this scan's outcome to the paid-plan licensing service
// and returns true if the org's quota is exhausted (in which case main
// should stop before running the PR comment/SARIF steps). It fails open:
// a licensing-service outage or network error is logged to stderr but does
// NOT block the scan — a billing hiccup on our end should never be the
// reason a paying customer's PR check goes red.
func reportUsage(licenseKey, apiBase string, findings []report.Finding, blocked bool) (quotaExceeded bool) {
	repoFullName := os.Getenv("GITHUB_REPOSITORY")
	if repoFullName == "" {
		fmt.Fprintln(os.Stderr, "tf-predeploy-firewall: TFPDF_LICENSE_KEY is set but GITHUB_REPOSITORY is not — skipping usage reporting for this run")
		return false
	}

	summaries := make([]licensing.FindingSummary, len(findings))
	for i, f := range findings {
		summaries[i] = licensing.FindingSummary{
			Category: string(f.Category), Severity: string(f.Severity), Resource: f.Resource,
			FilePath: f.File, Line: f.Line, Message: f.Message,
		}
	}

	client := licensing.NewClient(licenseKey, apiBase)
	allowed, reason, err := client.RecordScan(licensing.ScanResult{
		RepoFullName: repoFullName,
		FindingCount: len(findings),
		Blocked:      blocked,
		Findings:     summaries,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: usage reporting failed (scan still ran): %v\n", err)
		return false
	}
	if !allowed {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %s\n", reason)
		return true
	}
	return false
}

// applyOrgPolicy fetches the org's centrally-managed Growth-tier policy (if
// any) and merges it onto cfg. Precedence, low to high: repo-local
// config.yml < org policy < env var. An operator can therefore always
// force a setting locally via env var even when an org policy exists —
// this is a deliberate escape hatch, not an oversight.
//
// Fails open: if the control plane is unreachable or the org has no
// policy, cfg is left exactly as loadConfig produced it. A policy-fetch
// failure must never be the reason a scan doesn't run.
func applyOrgPolicy(cfg *config, licenseKey, apiBase string) {
	client := licensing.NewClient(licenseKey, apiBase)
	policy, err := client.GetPolicy(os.Getenv("GITHUB_REPOSITORY"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: fetching org policy failed, using local config (%v)\n", err)
		return
	}
	if policy == nil {
		return
	}

	if policy.BlockThreshold != nil && os.Getenv("SCANNER_BLOCK_THRESHOLD") == "" {
		cfg.BlockThreshold = report.Severity(*policy.BlockThreshold)
	}
	if len(policy.IgnoreRules) > 0 {
		// Centralized policy replaces the repo-local ignore list rather than
		// merging with it — the whole point of a team policy is that a
		// single repo's config.yml can't quietly opt out of it.
		cfg.IgnoreRules = make([]report.Category, len(policy.IgnoreRules))
		for i, c := range policy.IgnoreRules {
			cfg.IgnoreRules[i] = report.Category(c)
		}
	}
	if policy.PlanBlastRadiusThreshold != nil && os.Getenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD") == "" {
		cfg.PlanBlastRadiusThreshold = *policy.PlanBlastRadiusThreshold
	}
	if policy.CostImpactThresholdUSD != nil && os.Getenv("SCANNER_COST_IMPACT_THRESHOLD_USD") == "" {
		cfg.CostImpactThresholdUSD = *policy.CostImpactThresholdUSD
	}
	if policy.CustomRulesYAML != nil {
		cfg.CustomRulesYAMLOverride = *policy.CustomRulesYAML
	}
	if len(policy.RequireSecondReviewerUsers) > 0 {
		cfg.RequireSecondReviewerUsers = policy.RequireSecondReviewerUsers
	}
	if len(policy.RequireSecondReviewerTeams) > 0 {
		cfg.RequireSecondReviewerTeams = policy.RequireSecondReviewerTeams
	}
}

// applyWaivers fetches the repo's active waivers (Starter+, GET
// /v1/waivers) and marks every finding that matches one as Waived, with
// its justification attached. Matching is by category+resource+file, not
// line — see licensing.Waiver's doc comment. Fails open: if the control
// plane is unreachable, findings are returned unmodified, same as
// applyOrgPolicy — a control-plane hiccup must never silently waive (or
// fail to waive) a finding.
func applyWaivers(findings []report.Finding, licenseKey, apiBase string) []report.Finding {
	repoFullName := os.Getenv("GITHUB_REPOSITORY")
	if repoFullName == "" {
		return findings
	}

	client := licensing.NewClient(licenseKey, apiBase)
	waivers, err := client.GetWaivers(repoFullName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: fetching waivers failed, no findings waived (%v)\n", err)
		return findings
	}
	if len(waivers) == 0 {
		return findings
	}

	type waiverKey struct{ category, resource, file string }
	byKey := make(map[waiverKey]string, len(waivers))
	for _, w := range waivers {
		byKey[waiverKey{w.Category, w.Resource, w.FilePath}] = w.Justification
	}

	for i, f := range findings {
		if note, ok := byKey[waiverKey{string(f.Category), f.Resource, f.File}]; ok {
			findings[i].Waived = true
			findings[i].WaiverNote = note
		}
	}
	return findings
}

func blockedBy(findings []report.Finding, threshold report.Severity) bool {
	for _, f := range findings {
		if f.Waived {
			continue
		}
		if f.Severity.AtLeast(threshold) {
			return true
		}
	}
	return false
}

// loadCustomRules reads the `custom_rules:` section from the same YAML
// config file used by loadConfig. Returns (nil, nil) when the file is
// missing or defines no custom rules — a Growth+ feature that most repos
// won't use, so its absence must never be an error.
func loadCustomRules(path string) (*customrules.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg, err := customrules.Load(data)
	if err != nil {
		return nil, fmt.Errorf("loading custom rules from %s: %w", path, err)
	}
	if len(cfg.Rules) == 0 {
		return nil, nil
	}
	return cfg, nil
}

func loadConfig(path string) (config, error) {
	cfg := config{BlockThreshold: report.SeverityHigh, PlanBlastRadiusThreshold: 10}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return cfg, fmt.Errorf("reading config %s: %w", path, err)
	}
	// A missing config file just means "use the defaults above" — env var
	// overrides below must still apply either way, so this falls through
	// instead of returning early.
	if err == nil {
		// PlanBlastRadiusThreshold keeps its default of 10 unless the YAML
		// explicitly sets plan_blast_radius_threshold (yaml.Unmarshal only
		// overwrites fields present in the document).
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parsing config %s: %w", path, err)
		}
		if cfg.BlockThreshold == "" {
			cfg.BlockThreshold = report.SeverityHigh
		}
	}
	if env := os.Getenv("SCANNER_BLOCK_THRESHOLD"); env != "" {
		cfg.BlockThreshold = report.Severity(env)
	}
	if env := os.Getenv("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD"); env != "" {
		n, err := strconv.Atoi(env)
		if err != nil {
			return cfg, fmt.Errorf("SCANNER_PLAN_BLAST_RADIUS_THRESHOLD must be an integer, got %q: %w", env, err)
		}
		cfg.PlanBlastRadiusThreshold = n
	}
	if env := os.Getenv("SCANNER_COST_IMPACT_THRESHOLD_USD"); env != "" {
		n, err := strconv.ParseFloat(env, 64)
		if err != nil {
			return cfg, fmt.Errorf("SCANNER_COST_IMPACT_THRESHOLD_USD must be a number, got %q: %w", env, err)
		}
		cfg.CostImpactThresholdUSD = n
	}
	return cfg, nil
}

// postToPR reads GitHub Actions context (GITHUB_TOKEN, GITHUB_REPOSITORY,
// GITHUB_EVENT_PATH) to upsert the report as a PR comment.
func postToPR(body string) error {
	client, err := githubPRClient()
	if err != nil {
		return err
	}
	return client.UpsertComment(body, report.Marker)
}

// githubPRClient builds a githubpr.Client from GitHub Actions context
// (GITHUB_TOKEN, GITHUB_REPOSITORY, GITHUB_EVENT_PATH/PR_NUMBER) — shared
// by postToPR and requestSecondReviewerIfCritical so both fail the same
// way when that context isn't available (e.g. running outside a PR event).
func githubPRClient() (*githubpr.Client, error) {
	token := os.Getenv("GITHUB_TOKEN")
	repoFull := os.Getenv("GITHUB_REPOSITORY")
	if token == "" || repoFull == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN/GITHUB_REPOSITORY not set")
	}
	parts := strings.SplitN(repoFull, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("unexpected GITHUB_REPOSITORY format: %s", repoFull)
	}

	prNumber, err := prNumberFromEvent()
	if err != nil {
		return nil, err
	}

	return &githubpr.Client{Token: token, Owner: parts[0], Repo: parts[1], PRNum: prNumber, APIBase: githubAPIBaseForTest}, nil
}

// githubAPIBaseForTest overrides the GitHub API base URL for tests only
// (empty in production, which makes githubpr.Client default to the real
// api.github.com). Never set outside a test binary.
var githubAPIBaseForTest string

// requestSecondReviewerIfCritical requests review from the configured
// users/teams when at least one critical-severity finding is present.
// Best-effort: a failure here (e.g. one of the configured usernames isn't
// a repo collaborator) is logged and never affects the scan's exit code —
// the block/exit-1 behavior from BlockThreshold is the actual enforcement
// mechanism; this is a courtesy nudge on top of it.
func requestSecondReviewerIfCritical(findings []report.Finding, cfg config) {
	if len(cfg.RequireSecondReviewerUsers) == 0 && len(cfg.RequireSecondReviewerTeams) == 0 {
		return
	}
	hasCritical := false
	for _, f := range findings {
		if !f.Waived && f.Severity == report.SeverityCritical {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		return
	}

	client, err := githubPRClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: skipping second-reviewer request: %v\n", err)
		return
	}
	if err := client.RequestReviewers(cfg.RequireSecondReviewerUsers, cfg.RequireSecondReviewerTeams); err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: requesting second reviewer failed: %v\n", err)
	}
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
