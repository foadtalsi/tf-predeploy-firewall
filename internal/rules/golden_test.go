package rules

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

var updateGolden = flag.Bool("update-golden", false, "rewrite the golden files from current behaviour")

// The tutorial-pattern detectors are the ones with real detection content —
// regex tables, entropy floors, a placeholder vocabulary — and they are also
// the ones that have already shipped a false positive. Moving them out of Go
// and into the declarative pack is exactly the kind of change that can alter
// behaviour without any test noticing, because the unit tests assert that
// *some* finding fired, not which ones and with what wording.
//
// This golden file is the guard: every finding the corpus produces, in full,
// pinned. A migration that changes one severity, drops one branch or reworks
// one message has to say so out loud by rewriting this file.
func TestGolden_TutorialPattern(t *testing.T) {
	kb := mustLoadSchema(t)

	fixtures := []string{
		"tutorial_golden.tf",
		"tutorial_pattern.tf",
		"credential_values.tf",
		"nested_block_cidr.tf",
	}

	var got []string
	for _, name := range fixtures {
		src, err := os.ReadFile(filepath.Join("../../testdata/fixtures", name))
		if err != nil {
			t.Fatalf("reading fixture %s: %v", name, err)
		}
		// Parsed with a scope built from the fixture itself, so a value
		// reached through a variable default resolves and sets ResolvedFrom.
		// Without it the corpus would never exercise the branch where a
		// finding names the reference and deliberately withholds the
		// one-click fix — the line under that finding is already correct.
		scope := parser.BuildScope(map[string][]byte{name: src})
		resources, err := parser.ParseFileWithContext(name, src, scope)
		if err != nil {
			t.Fatalf("parsing fixture %s: %v", name, err)
		}
		in := FileInput{Path: name, HeadResources: resources, HeadSource: src}
		got = append(got, renderFindings(tutorialPatternRule(t).Check(in, kb))...)
	}

	// Attribute iteration is map order, so the rule's own output order is not
	// stable. Sorting here is not hiding a problem: nothing downstream depends
	// on the order rules emit in, the report sorts before rendering.
	sort.Strings(got)
	actual := strings.Join(got, "\n") + "\n"

	goldenPath := "../../testdata/golden/tutorial_pattern.txt"
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatalf("creating golden dir: %v", err)
		}
		if err := os.WriteFile(goldenPath, []byte(actual), 0o644); err != nil {
			t.Fatalf("writing golden: %v", err)
		}
		t.Logf("golden rewritten: %d findings", len(got))
		return
	}

	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("reading golden (run: go test ./internal/rules -run TestGolden -update-golden): %v", err)
	}
	if string(want) != actual {
		t.Errorf("tutorial-pattern findings changed.\n%s", diffLines(string(want), actual))
	}
}

// renderFindings flattens a finding into one line per field that matters,
// including the one-click fix. A fix that silently stops being produced is a
// regression a message-only comparison would miss.
func renderFindings(findings []report.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		line := fmt.Sprintf("%s:%d | %s | %s | %s | %s",
			f.File, f.Line, f.Category, f.Severity, f.Resource, f.Message)
		if f.Suggestion != "" {
			line += " | suggestion=" + oneLine(f.Suggestion)
		}
		if f.Fix != nil {
			line += fmt.Sprintf(" | fix=%d-%d:%s", f.Fix.StartLine, f.Fix.EndLine, oneLine(f.Fix.Text()))
			if f.Fix.Note != "" {
				line += " | note=" + oneLine(f.Fix.Note)
			}
		}
		out = append(out, line)
	}
	return out
}

func oneLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", "\\n"), "\r", "")
}

// diffLines reports the first differing line plus the counts, which is enough
// to see what a migration changed without pulling in a diff library.
func diffLines(want, got string) string {
	w := strings.Split(strings.TrimRight(want, "\n"), "\n")
	g := strings.Split(strings.TrimRight(got, "\n"), "\n")

	var b strings.Builder
	fmt.Fprintf(&b, "want %d findings, got %d\n", len(w), len(g))

	inWant := map[string]bool{}
	for _, l := range w {
		inWant[l] = true
	}
	inGot := map[string]bool{}
	for _, l := range g {
		inGot[l] = true
	}
	for _, l := range w {
		if !inGot[l] {
			fmt.Fprintf(&b, "  -%s\n", l)
		}
	}
	for _, l := range g {
		if !inWant[l] {
			fmt.Fprintf(&b, "  +%s\n", l)
		}
	}
	return b.String()
}
