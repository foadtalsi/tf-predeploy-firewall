package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func mustLoadCostImpactPlan(t *testing.T) *planjson.PlanFile {
	t.Helper()
	pf, err := planjson.Load("../../testdata/plans/cost_impact_plan.json")
	if err != nil {
		t.Fatalf("planjson.Load: %v", err)
	}
	return pf
}

// cost_impact_plan.json:
//
//	aws_instance.web        create m5.2xlarge          -> +$280/mo
//	aws_instance.upsized    update t3.micro -> m5.large -> +$62.5/mo
//	aws_nat_gateway.old     destroy-only (flat $32)     -> -$32/mo
//	aws_iam_role.app        no-op                       -> unpriced/no-op, $0
//	data.aws_ami.al2023     data source read             -> skipped
//
// Total delta: 280 + 62.5 - 32 = 310.5

func TestCostImpactRule_Disabled(t *testing.T) {
	kb := mustLoadSchema(t)
	pf := mustLoadCostImpactPlan(t)

	findings := CostImpactRule{ThresholdUSD: 0}.Check("plan.json", pf.ResourceChanges, kb)
	if len(findings) != 0 {
		t.Errorf("expected no findings when threshold is 0 (disabled), got %#v", findings)
	}
}

func TestCostImpactRule_BelowThreshold(t *testing.T) {
	kb := mustLoadSchema(t)
	pf := mustLoadCostImpactPlan(t)

	// Total delta is 310.5; a threshold above that should not trigger.
	findings := CostImpactRule{ThresholdUSD: 1000}.Check("plan.json", pf.ResourceChanges, kb)
	if len(findings) != 0 {
		t.Errorf("expected no findings below threshold, got %#v", findings)
	}
}

func TestCostImpactRule_AboveThreshold(t *testing.T) {
	kb := mustLoadSchema(t)
	pf := mustLoadCostImpactPlan(t)

	findings := CostImpactRule{ThresholdUSD: 100}.Check("plan.json", pf.ResourceChanges, kb)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 aggregate finding, got %d: %#v", len(findings), findings)
	}
	f := findings[0]
	if f.Category != report.CategoryCostImpact {
		t.Errorf("unexpected category: %s", f.Category)
	}
	if !strings.Contains(f.Message, "aws_instance.web") {
		t.Errorf("expected top contributor aws_instance.web mentioned, got: %s", f.Message)
	}
	if !strings.Contains(f.Message, "aws_instance.upsized") {
		t.Errorf("expected top contributor aws_instance.upsized mentioned, got: %s", f.Message)
	}
}

func TestCostImpactRule_SeverityEscalatesAtFiveXThreshold(t *testing.T) {
	kb := mustLoadSchema(t)
	pf := mustLoadCostImpactPlan(t)

	// Total delta 310.5 >= 5*50 (250) => high severity.
	high := CostImpactRule{ThresholdUSD: 50}.Check("plan.json", pf.ResourceChanges, kb)
	if len(high) != 1 || high[0].Severity != report.SeverityHigh {
		t.Fatalf("expected high severity at 5x threshold, got %#v", high)
	}

	// Total delta 310.5 < 5*100 (500) => medium severity.
	medium := CostImpactRule{ThresholdUSD: 100}.Check("plan.json", pf.ResourceChanges, kb)
	if len(medium) != 1 || medium[0].Severity != report.SeverityMedium {
		t.Fatalf("expected medium severity below 5x threshold, got %#v", medium)
	}
}

func TestCostImpactRule_SkipsDataSourcesAndNoOps(t *testing.T) {
	kb := mustLoadSchema(t)
	pf := mustLoadCostImpactPlan(t)

	findings := CostImpactRule{ThresholdUSD: 1}.Check("plan.json", pf.ResourceChanges, kb)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 aggregate finding, got %d: %#v", len(findings), findings)
	}
	if strings.Contains(findings[0].Message, "aws_iam_role.app") {
		t.Errorf("no-op resource should not contribute to the finding, got: %s", findings[0].Message)
	}
	if strings.Contains(findings[0].Message, "aws_ami") {
		t.Errorf("data source should not contribute to the finding, got: %s", findings[0].Message)
	}
}

func TestCostImpactRule_UnpricedResourceTypeContributesZero(t *testing.T) {
	kb := mustLoadSchema(t)

	changes := []planjson.ResourceChange{
		{
			Address: "aws_cloudfront_distribution.cdn",
			Mode:    "managed",
			Type:    "aws_cloudfront_distribution",
			Change: planjson.Change{
				Actions: []string{"create"},
				Before:  nil,
				After:   map[string]interface{}{"enabled": true},
			},
		},
	}

	findings := CostImpactRule{ThresholdUSD: 1}.Check("plan.json", changes, kb)
	if len(findings) != 0 {
		t.Errorf("expected no findings for an unpriced resource type, got %#v", findings)
	}
}
