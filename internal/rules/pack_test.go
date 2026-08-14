package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/ruledef"
)

func mustPack(t *testing.T, yaml string) *ruledef.Pack {
	t.Helper()
	p, err := ruledef.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("loading pack: %v", err)
	}
	return p
}

// A rule naming something this binary does not implement must stop the scan.
// Skipping it instead would leave the rule loaded, matching nothing, while
// the run still reported success — which is indistinguishable from a clean
// repository.
func TestValidatePredicates_RejectsUnknownNames(t *testing.T) {
	p := mustPack(t, `
version: 1
rules:
  - id: a
    category: c
    severity: low
    message: m
    match:
      scope: attribute
      literal: true
      value_matches: 'x'
      confirm: measure_the_vibes
`)
	err := validatePredicates(p)
	if err == nil {
		t.Fatal("expected an error for the unknown confirm predicate")
	}
	if !strings.Contains(err.Error(), "measure_the_vibes") {
		t.Errorf("error must name the offending predicate, got %q", err)
	}
	// Naming what IS available turns a dead end into a fixable typo.
	if !strings.Contains(err.Error(), "base64_secret") {
		t.Errorf("error should list the available predicates, got %q", err)
	}
}

func TestFromPack_RejectsUnknownEngine(t *testing.T) {
	p := mustPack(t, `
version: 1
rules:
  - id: a
    category: c
    severity: low
    engine: read_the_authors_mind
`)
	if _, err := FromPack(p, Options{}); err == nil {
		t.Fatal("expected an error for the unknown engine")
	}
}

// The cost rule is the one engine that can decline to run. Zero means off,
// and off must mean absent rather than present-and-silent.
func TestFromPack_StaticCostRespectsThreshold(t *testing.T) {
	p := mustPack(t, `
version: 1
rules:
  - id: static_cost
    category: cost_impact
    severity: medium
    engine: static_cost
    params:
      threshold_usd: "0"
`)
	off, err := FromPack(p, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(off) != 0 {
		t.Errorf("threshold 0 must leave the rule out entirely, got %d rules", len(off))
	}

	on, err := FromPack(p, Options{CostThresholdUSD: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(on) != 1 {
		t.Fatalf("expected the cost rule, got %d rules", len(on))
	}
	if got := on[0].(StaticCostRule).ThresholdUSD; got != 50 {
		t.Errorf("threshold = %v, want 50 (the flag must win over the pack default)", got)
	}
}

func TestFromPack_ParamsAreValidated(t *testing.T) {
	p := mustPack(t, `
version: 1
rules:
  - id: static_cost
    category: cost_impact
    severity: medium
    engine: static_cost
    params:
      threshold_usd: "quite a lot"
`)
	if _, err := FromPack(p, Options{}); err == nil {
		t.Fatal("expected an error for a non-numeric threshold")
	}
}

// The whole group must resolve to a single rule, or first-match-wins has
// nothing to arbitrate between and the fallback fires alongside the specific
// formats instead of behind them.
func TestFromPack_GroupBecomesOneRule(t *testing.T) {
	ruleset, err := FromPack(BuiltinPack(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	groupMembers := len(BuiltinPack().Group("credential_value"))
	if groupMembers < 2 {
		t.Fatalf("expected a multi-member group, got %d", groupMembers)
	}

	var declarative int
	for _, r := range ruleset {
		if d, ok := r.(declarativeRule); ok && d.specs[0].Group == "credential_value" {
			declarative++
			if len(d.specs) != groupMembers {
				t.Errorf("group rule holds %d specs, want all %d", len(d.specs), groupMembers)
			}
		}
	}
	if declarative != 1 {
		t.Errorf("the credential_value group produced %d rules, want exactly 1", declarative)
	}
}

// These four are how internal/tfvars and internal/terragrunt judge a value,
// and they read the pack rather than keeping their own copy of the patterns.
// A pack change that broke them would silently stop those scanners finding
// secrets while the resource scanner carried on working.
func TestExportedHelpers_ReadThePack(t *testing.T) {
	if !IsCredentialAttrName("administrator_login_password") {
		t.Error("suffix credential names must be recognised")
	}
	if IsCredentialAttrName("partition_key") {
		t.Error("partition_key is not a credential")
	}

	if label, ok := MatchCredentialValuePattern("AKIAIOSFODNN7EXAMPLE"); !ok {
		t.Error("an AWS access key ID must be recognised")
	} else if !strings.Contains(label, "AKIA") {
		t.Errorf("label %q should name the format", label)
	}
	if _, ok := MatchCredentialValuePattern("infra/terraform/build/dashboard/bootstrap"); ok {
		t.Error("a file path is not a secret — this was a real false positive")
	}

	if !IsOpenCIDR("0.0.0.0/0") {
		t.Error("0.0.0.0/0 must be recognised as open")
	}
	if IsOpenCIDR("10.0.0.0/8") {
		t.Error("a private range is not open")
	}
}

// Expansion has to leave HCL alone: a fix template writes Terraform, and
// Terraform is full of braces that are not placeholders.
func TestExpand_LeavesNonPlaceholderBracesAlone(t *testing.T) {
	got := expand(`variable "{var}" {
  type = string
}
locals { x = "${var.other}" }`, map[string]string{"var": "db_password"})

	want := `variable "db_password" {
  type = string
}
locals { x = "${var.other}" }`

	if got != want {
		t.Errorf("expand mangled the template:\ngot:  %q\nwant: %q", got, want)
	}
}

func TestExpand_UnknownPlaceholderSurvives(t *testing.T) {
	if got := expand("{attr} and {nope}", map[string]string{"attr": "password"}); got != "password and {nope}" {
		t.Errorf("got %q", got)
	}
}
