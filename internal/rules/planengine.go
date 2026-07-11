package rules

import (
	"github.com/foadtalsi/tf-predeploy-firewall/internal/ignore"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// PlanRuleConfig configures the phase-2 plan-based rules.
type PlanRuleConfig struct {
	// BlastRadiusThreshold is the number of destroy/replace actions that
	// triggers BlastRadiusRule. Zero disables the rule.
	BlastRadiusThreshold int
	// GlobalIgnore suppresses these categories, same as the static scan.
	GlobalIgnore []report.Category
}

// RunPlanRules runs every phase-2 rule against a parsed `terraform show
// -json` plan. planPath is used to attribute findings to a pseudo-file
// (the plan itself has no .tf line numbers). changedAttrs should come from
// the static Run's Result.ChangedAttrs so DriftRule can tell an
// intentional PR change from unexplained drift.
func RunPlanRules(planPath string, pf *planjson.PlanFile, changedAttrs map[string]map[ChangedAttrKey]bool, aws *schema.AWS, cfg PlanRuleConfig) []report.Finding {
	var findings []report.Finding

	findings = append(findings, ConfirmedReplaceRule{}.Check(planPath, pf.ResourceChanges, aws)...)
	findings = append(findings, DriftRule{}.Check(planPath, pf.ResourceChanges, changedAttrs, aws)...)
	findings = append(findings, BlastRadiusRule{Threshold: cfg.BlastRadiusThreshold}.Check(planPath, pf.ResourceChanges, aws)...)

	// No per-line inline ignore directives apply to plan-derived findings
	// (there's no .tf source line to attach a comment to); only the global
	// config-level ignore list applies here.
	return ignore.Apply(findings, nil, cfg.GlobalIgnore)
}

// DeduplicateForceNewAgainstPlan drops phase-1 ForceNewChangeRule findings
// (a heuristic guess from a curated attribute list) for any resource that
// phase-2's ConfirmedReplaceRule already reported from the real plan. Both
// rules fire for the same underlying problem — "this attribute change
// destroys and recreates the resource" — and once a plan confirms it,
// repeating the heuristic guess is just noise on top of a certainty.
func DeduplicateForceNewAgainstPlan(staticFindings, planFindings []report.Finding) []report.Finding {
	confirmed := make(map[string]bool)
	for _, f := range planFindings {
		if f.Category == report.CategoryConfirmedReplace {
			confirmed[bareResourceAddress(f.Resource)] = true
		}
	}
	if len(confirmed) == 0 {
		return staticFindings
	}

	out := make([]report.Finding, 0, len(staticFindings))
	for _, f := range staticFindings {
		if f.Category == report.CategoryForceNewChange && confirmed[bareResourceAddress(f.Resource)] {
			continue
		}
		out = append(out, f)
	}
	return out
}
