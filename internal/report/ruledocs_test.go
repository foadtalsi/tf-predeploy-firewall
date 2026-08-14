package report

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateDocs = flag.Bool("update", false, "rewrite docs/rules.md from ruleHelps")

const rulesDocPath = "../../docs/rules.md"

// Every SARIF rule's helpUri points at a section of docs/rules.md. A category
// with no section is a dead link in whoever's security dashboard uploaded the
// SARIF — so the file is generated, and this keeps it in sync.
func TestRuleDocs_FileMatchesRuleHelps(t *testing.T) {
	want := RenderRuleDocs()

	if *updateDocs {
		if err := os.MkdirAll(filepath.Dir(rulesDocPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(rulesDocPath, []byte(want), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("wrote " + rulesDocPath)
		return
	}

	got, err := os.ReadFile(rulesDocPath)
	if err != nil {
		t.Fatalf("%v — run: go test ./internal/report -run TestRuleDocs -update", err)
	}
	if string(got) != want {
		t.Error("docs/rules.md is out of date — run: go test ./internal/report -run TestRuleDocs -update")
	}
}

// A rule that ships without an explanation is a rule that gets switched off
// rather than understood.
func TestRuleDocs_EveryRuleIsDocumented(t *testing.T) {
	for _, r := range sarifRules {
		c := Category(r.ID)
		h, ok := ruleHelps[c]
		if !ok {
			t.Errorf("category %q has a SARIF rule but no help text", c)
			continue
		}
		if h.fullDescription == "" || h.markdown == "" {
			t.Errorf("category %q has empty help", c)
		}
		// Every rule must say how to disagree with it, or the only available
		// response to a false positive is to uninstall the tool.
		if !strings.Contains(h.markdown, "tf-firewall-ignore") &&
			!strings.Contains(h.markdown, "ignore_paths") &&
			!strings.Contains(h.markdown, "threshold") {
			t.Errorf("category %q never explains how to suppress or tune it", c)
		}
	}
}

func TestDescribedRules_CarryHelpAndURI(t *testing.T) {
	for _, r := range describedRules() {
		if r.HelpURI == "" {
			t.Errorf("rule %q has no helpUri", r.ID)
		}
		if !strings.HasSuffix(r.HelpURI, "#"+r.ID) {
			t.Errorf("rule %q helpUri %q must anchor on the category id", r.ID, r.HelpURI)
		}
		if r.Help == nil || r.Help.Markdown == "" {
			t.Errorf("rule %q has no rendered help — the Code Scanning alert page would be a bare message", r.ID)
		}
	}
	// The source list must stay untouched: describedRules copies it, and a
	// mutation there would leak between calls.
	for _, r := range sarifRules {
		if r.HelpURI != "" || r.Help != nil {
			t.Error("describedRules must not mutate sarifRules")
		}
	}
}
