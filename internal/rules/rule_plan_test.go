package rules

import (
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func mustLoadPlan(t *testing.T) *planjson.PlanFile {
	t.Helper()
	pf, err := planjson.Load("../../testdata/plans/sample_plan.json")
	if err != nil {
		t.Fatalf("planjson.Load: %v", err)
	}
	return pf
}

// sample_plan.json:
//   aws_db_instance.prod        -> replace (delete+create), critical resource type
//   aws_s3_bucket.logs          -> destroy-only, critical resource type
//   aws_security_group.web     -> pure update (name/description unchanged; description text differs)
//   aws_iam_role.app            -> no-op

func TestConfirmedReplaceRule(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadPlan(t)

	findings := ConfirmedReplaceRule{}.Check("plan.json", pf.ResourceChanges, aws)

	byResource := map[string]report.Finding{}
	for _, f := range findings {
		byResource[f.Resource] = f
	}

	replace, ok := byResource["aws_db_instance.prod"]
	if !ok {
		t.Fatal("expected a finding for aws_db_instance.prod (replace)")
	}
	if replace.Severity != report.SeverityCritical {
		t.Errorf("expected critical severity for replace on critical resource, got %s", replace.Severity)
	}

	destroy, ok := byResource["aws_s3_bucket.logs"]
	if !ok {
		t.Fatal("expected a finding for aws_s3_bucket.logs (destroy-only)")
	}
	if destroy.Severity != report.SeverityCritical {
		t.Errorf("expected critical severity for destroy-only on critical resource, got %s", destroy.Severity)
	}

	if _, ok := byResource["aws_iam_role.app"]; ok {
		t.Error("did not expect a finding for a no-op resource")
	}
	if _, ok := byResource["aws_security_group.web"]; ok {
		t.Error("did not expect a finding for a pure update")
	}
}

func TestBlastRadiusRule_BelowThreshold(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadPlan(t)

	// sample_plan.json has 2 destroy/replace actions; threshold 10 => no finding.
	findings := BlastRadiusRule{Threshold: 10}.Check("plan.json", pf.ResourceChanges, aws)
	if len(findings) != 0 {
		t.Errorf("expected no blast-radius finding below threshold, got %#v", findings)
	}
}

func TestBlastRadiusRule_AboveThreshold(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadPlan(t)

	// 2 destructive changes in the fixture; threshold 2 should trigger.
	findings := BlastRadiusRule{Threshold: 2}.Check("plan.json", pf.ResourceChanges, aws)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 aggregate finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Category != report.CategoryLargeBlastRadius {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
}

func TestBlastRadiusRule_Disabled(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadPlan(t)

	findings := BlastRadiusRule{Threshold: 0}.Check("plan.json", pf.ResourceChanges, aws)
	if len(findings) != 0 {
		t.Errorf("expected no findings when threshold is 0 (disabled), got %#v", findings)
	}
}

func TestDriftRule_FlagsUntouchedSensitiveAttr(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadPlan(t)

	// aws_security_group.web is a pure update in the plan changing "name" and
	// "description"; aws_forcenew_attrs.json lists "name" as ForceNew/top-level
	// for aws_security_group. No changedAttrs supplied => PR's .tf diff never
	// touched it => should be flagged as drift.
	findings := DriftRule{}.Check("plan.json", pf.ResourceChanges, map[string]map[ChangedAttrKey]bool{}, aws)

	found := false
	for _, f := range findings {
		if f.Resource == "aws_security_group.web" && f.Category == report.CategoryUnexpectedDrift {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an unexpected_drift finding for aws_security_group.web, got %#v", findings)
	}
}

func TestDriftRule_SuppressedWhenPRExplainsChange(t *testing.T) {
	aws := mustLoadSchema(t)
	pf := mustLoadPlan(t)

	// Same plan, but this time the PR's own diff DID touch "name" on that
	// resource — so it's an intentional change, not drift.
	changedAttrs := map[string]map[ChangedAttrKey]bool{
		"aws_security_group.web": {"name": true},
	}
	findings := DriftRule{}.Check("plan.json", pf.ResourceChanges, changedAttrs, aws)

	for _, f := range findings {
		if f.Resource == "aws_security_group.web" {
			t.Errorf("did not expect a drift finding once the PR diff explains the change, got %#v", f)
		}
	}
}
