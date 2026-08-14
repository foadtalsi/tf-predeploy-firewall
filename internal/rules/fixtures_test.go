package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

// deliberatelyInvalidFixtures exist to be wrong — that is what they test.
// Everything else has to be Terraform somebody could actually apply.
var deliberatelyInvalidFixtures = map[string]string{
	"unknown_attribute.tf": "its whole purpose is to carry an argument no provider declares",
}

// The scanner must not flag its own corpus.
//
// This started as a real defect: the tutorial-pattern corpus reached for
// attribute names like administrator_login_password on aws_db_instance
// purely because they exercised the credential-name matcher, and seven of
// them existed on no provider anywhere. The fixture was therefore testing
// detection against Terraform nobody could ever write, and the scanner
// reported its own test data as hallucinated.
//
// The fix was to move each attribute onto a resource type that genuinely
// declares it. This test is what keeps it fixed, because the mistake is
// invisible from inside the tutorial-pattern tests — they pass either way.
//
// It catches attributes that exist nowhere. It cannot catch a *missing*
// required argument, because the rule packs record which arguments exist and
// not which are mandatory — and a fixture missing one is red in an editor
// just the same. testdata/validate-fixtures.sh covers that half against the
// real provider schemas; run it when adding or editing a fixture.
func TestFixtures_AreValidTerraform(t *testing.T) {
	kb := mustLoadSchema(t)
	ruleset := DefaultRules(Options{})

	entries, err := os.ReadDir("../../testdata/fixtures")
	if err != nil {
		t.Fatalf("reading fixtures: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tf") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("../../testdata/fixtures", e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			resources, err := parser.ParseFile(e.Name(), src)
			if err != nil {
				t.Fatalf("fixture does not parse as HCL: %v", err)
			}

			in := FileInput{Path: e.Name(), HeadResources: resources, HeadSource: src}
			var invented []string
			for _, rule := range ruleset {
				for _, f := range rule.Check(in, kb) {
					if f.Category == report.CategoryUnknownAttribute {
						invented = append(invented, f.Message)
					}
				}
			}

			if why, expected := deliberatelyInvalidFixtures[e.Name()]; expected {
				if len(invented) == 0 {
					t.Errorf("%s is listed as deliberately invalid (%s) but the scanner found nothing wrong with it — either the fixture or the rule has stopped doing its job",
						e.Name(), why)
				}
				return
			}

			for _, msg := range invented {
				t.Errorf("the scanner flags its own fixture: %s\n"+
					"Put the attribute on a resource type that really declares it. "+
					"A corpus the tool rejects has stopped describing reality.", msg)
			}
		})
	}
}
