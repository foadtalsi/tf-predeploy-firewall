package rules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
)

// The insecure_config group is pinned against the FULL default rule set
// rather than one category's detectors, and against two fixtures rather than
// one.
//
// Both choices answer the same weakness. A per-category golden proves a rule
// still fires; it cannot show that widening one rule's pattern started
// double-reporting a line another rule already covered, because the other
// rule is not running. And a corpus of only positive cases proves detection
// and says nothing about noise — which is the failure mode that actually
// matters here, since a scanner people mute finds nothing at all.
//
// So insecure_config_clean.tf is in the same golden. Its findings are
// expected to be exactly the ones other categories produce (missing_lifecycle
// on the stateful types) and nothing from this group. Loosening a pattern to
// catch one more real case shows up immediately as a new line under the clean
// fixture.
func TestGolden_InsecureConfig(t *testing.T) {
	kb := mustLoadSchema(t)
	ruleset := DefaultRules(Options{})

	fixtures := []string{
		"insecure_config.tf",
		"insecure_config_clean.tf",
	}

	var got []string
	for _, name := range fixtures {
		src, err := os.ReadFile(filepath.Join("../../testdata/fixtures", name))
		if err != nil {
			t.Fatalf("reading fixture %s: %v", name, err)
		}
		scope := parser.BuildScope(map[string][]byte{name: src})
		resources, err := parser.ParseFileWithContext(name, src, scope)
		if err != nil {
			t.Fatalf("parsing fixture %s: %v", name, err)
		}
		in := FileInput{Path: name, HeadResources: resources, HeadSource: src}
		for _, r := range ruleset {
			got = append(got, renderFindings(r.Check(in, kb))...)
		}
	}

	sort.Strings(got)
	actual := strings.Join(got, "\n") + "\n"

	goldenPath := "../../testdata/golden/insecure_config.txt"
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
		t.Errorf("insecure_config findings changed.\n%s", diffLines(string(want), actual))
	}
}

// The clean fixture is the point of the pair, so it gets its own assertion
// rather than being left to a reader of the golden file to verify. A golden
// diff says "something changed"; this says which promise broke.
func TestInsecureConfig_CleanFixtureProducesNoGroupFindings(t *testing.T) {
	kb := mustLoadSchema(t)

	const name = "insecure_config_clean.tf"
	src, err := os.ReadFile(filepath.Join("../../testdata/fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	scope := parser.BuildScope(map[string][]byte{name: src})
	resources, err := parser.ParseFileWithContext(name, src, scope)
	if err != nil {
		t.Fatal(err)
	}
	in := FileInput{Path: name, HeadResources: resources, HeadSource: src}

	group := map[string]bool{
		"public_exposure":     true,
		"encryption_disabled": true,
		"permissive_iam":      true,
		"audit_disabled":      true,
	}

	for _, r := range DefaultRules(Options{}) {
		for _, f := range r.Check(in, kb) {
			if group[string(f.Category)] {
				t.Errorf("false positive on correct Terraform: %s:%d [%s] %s",
					f.File, f.Line, f.Category, f.Message)
			}
			// skip_final_snapshot files under missing_lifecycle, so it needs
			// naming rather than category-matching.
			if strings.Contains(f.Message, "skip_final_snapshot") {
				t.Errorf("false positive on correct Terraform: %s:%d %s", f.File, f.Line, f.Message)
			}
		}
	}
}
