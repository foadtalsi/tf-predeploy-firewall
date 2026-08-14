package main

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/rules"
)

// runRulesDryRun answers the question every custom-rule author has and the
// real scan can't safely answer: "what would this rule match, today, across
// the whole repo?" — without failing CI, posting comments, or reporting
// usage. Returns the process exit code.
//
// It exits 0 even when rules match: matches here are the author's feedback
// loop, not violations. The one thing that does exit non-zero is a rule
// file that doesn't load, because a config that can't parse would fail the
// real scan too, and this is the place to find that out.
func runRulesDryRun(configPath, repoDir string) int {
	custom, err := loadCustomRules(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		return 2
	}
	if custom == nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: no custom_rules in %s — nothing to dry-run\n", configPath)
		return 2
	}

	files, err := diff.AllTerraformFiles(repoDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		return 2
	}

	// Only the custom rules run: the built-ins have their own tests, and
	// mixing their findings in would bury the signal the author came for.
	// No ignores either — an author needs to see what a rule REALLY
	// matches; the real scan applies suppressions later.
	result, err := rules.Run(files, nil, []rules.Rule{custom.AsEngineRule()}, rules.RunOptions{RepoDir: repoDir})
	if err != nil {
		fmt.Fprintf(os.Stderr, "tf-predeploy-firewall: %v\n", err)
		return 2
	}

	byRule := map[string][]report.Finding{}
	for _, f := range result.Findings {
		id := strings.TrimPrefix(string(f.Category), "custom:")
		byRule[id] = append(byRule[id], f)
	}

	fmt.Printf("dry run: %d custom rule(s) against %d .tf file(s) in %s\n\n", len(custom.Rules), len(files), repoDir)
	for _, r := range custom.Rules {
		matches := byRule[r.ID]
		// "matched nothing" is the line an author most needs to see — a
		// rule that silently matches nothing is indistinguishable from a
		// working one until the incident it should have caught.
		fmt.Printf("rule %q: %d match(es)\n", r.ID, len(matches))
		sort.Slice(matches, func(i, j int) bool {
			if matches[i].File != matches[j].File {
				return matches[i].File < matches[j].File
			}
			return matches[i].Line < matches[j].Line
		})
		for _, m := range matches {
			fmt.Printf("  %s:%d  %s  [%s] %s\n", m.File, m.Line, m.Resource, m.Severity, m.Message)
		}
		fmt.Println()
	}
	return 0
}
