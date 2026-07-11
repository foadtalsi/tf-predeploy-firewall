package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func mustLoadEdgeCasePlan(t *testing.T) *planjson.PlanFile {
	t.Helper()
	pf, err := planjson.Load("../../testdata/plans/sensitive_and_modules_plan.json")
	if err != nil {
		t.Fatalf("planjson.Load: %v", err)
	}
	return pf
}

func TestDriftRule_MatchesModuleAddressAgainstBareChangedAttrs(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadEdgeCasePlan(t)

	// changedAttrs uses the bare "type.name" key the HCL parser produces —
	// no module prefix — because this PR's .tf diff DID touch "identifier".
	changedAttrs := map[string]map[ChangedAttrKey]bool{
		"aws_db_instance.primary": {"identifier": true},
	}
	findings := DriftRule{}.Check("plan.json", pf.ResourceChanges, changedAttrs, aws)

	for _, f := range findings {
		if f.Resource == "module.db.aws_db_instance.primary" {
			t.Errorf("expected the module-prefixed change to be recognized as explained by the PR diff, got finding: %s", f.Message)
		}
	}
}

func TestDriftRule_FlagsModuleAddressWhenNotExplained(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadEdgeCasePlan(t)

	findings := DriftRule{}.Check("plan.json", pf.ResourceChanges, map[string]map[ChangedAttrKey]bool{}, aws)

	found := false
	for _, f := range findings {
		if f.Resource == "module.db.aws_db_instance.primary" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a drift finding for the module-addressed resource when no changedAttrs explain it")
	}
}

func TestDriftRule_RedactsSensitiveValues(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadEdgeCasePlan(t)

	findings := DriftRule{}.Check("plan.json", pf.ResourceChanges, map[string]map[ChangedAttrKey]bool{}, aws)

	var kmsFinding *report.Finding
	for i, f := range findings {
		if f.Resource == "aws_kms_key.secret" {
			kmsFinding = &findings[i]
		}
	}
	if kmsFinding == nil {
		t.Fatal("expected a drift finding for aws_kms_key.secret")
	}
	if strings.Contains(kmsFinding.Message, "s3cr3t-value-here") {
		t.Errorf("sensitive value leaked into finding message: %s", kmsFinding.Message)
	}
	if !strings.Contains(kmsFinding.Message, "redacted") {
		t.Errorf("expected message to indicate redaction, got: %s", kmsFinding.Message)
	}
}

func TestDriftRule_SkipsDataSources(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadEdgeCasePlan(t)

	findings := DriftRule{}.Check("plan.json", pf.ResourceChanges, map[string]map[ChangedAttrKey]bool{}, aws)

	for _, f := range findings {
		if f.Resource == "data.aws_db_instance.lookup" {
			t.Errorf("did not expect a finding for a data source read, got: %s", f.Message)
		}
	}
}

func TestConfirmedReplaceRule_SkipsDataSources(t *testing.T) {
	aws := mustLoadSchema(t)
	// A data source can never appear with delete/replace actions in
	// practice, but the rule should filter by mode regardless of actions
	// as defense in depth.
	changes := []planjson.ResourceChange{
		{
			Address: "data.aws_db_instance.lookup",
			Mode:    "data",
			Type:    "aws_db_instance",
			Change:  planjson.Change{Actions: []string{"delete"}},
		},
	}
	findings := ConfirmedReplaceRule{}.Check("plan.json", changes, aws)
	if len(findings) != 0 {
		t.Errorf("expected no findings for a data source, got %#v", findings)
	}
}

func TestDeduplicateForceNewAgainstPlan(t *testing.T) {
	staticFindings := []report.Finding{
		{Resource: "aws_db_instance.prod", Category: report.CategoryForceNewChange, Message: "heuristic guess"},
		{Resource: "aws_instance.web", Category: report.CategoryForceNewChange, Message: "unrelated heuristic guess"},
		{Resource: "aws_db_instance.prod", Category: report.CategoryMissingLifecycle, Message: "unrelated category"},
	}
	planFindings := []report.Finding{
		{Resource: "aws_db_instance.prod", Category: report.CategoryConfirmedReplace, Message: "confirmed by plan"},
	}

	out := DeduplicateForceNewAgainstPlan(staticFindings, planFindings)

	if len(out) != 2 {
		t.Fatalf("expected 2 findings after dedup (unrelated heuristic + unrelated category), got %d: %#v", len(out), out)
	}
	for _, f := range out {
		if f.Resource == "aws_db_instance.prod" && f.Category == report.CategoryForceNewChange {
			t.Error("expected the ForceNewChange finding for aws_db_instance.prod to be removed")
		}
	}
}

func TestDeduplicateForceNewAgainstPlan_NoOpWithoutConfirmedReplace(t *testing.T) {
	staticFindings := []report.Finding{
		{Resource: "aws_db_instance.prod", Category: report.CategoryForceNewChange, Message: "heuristic guess"},
	}
	out := DeduplicateForceNewAgainstPlan(staticFindings, nil)
	if len(out) != 1 {
		t.Errorf("expected static findings untouched when there are no plan findings, got %#v", out)
	}
}
