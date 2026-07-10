package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// ConfirmedReplaceRule inspects a real `terraform plan` and flags any
// resource that Terraform has actually decided to destroy — either a pure
// delete, or a delete+create replace — on a stateful/critical resource
// type. Unlike ForceNewChangeRule (phase 1), which guesses from a ForceNew
// attribute list, this is not a heuristic: it's what Terraform itself will
// do on apply.
type ConfirmedReplaceRule struct{}

// Check runs the rule over every resource_changes entry in the plan.
// planPath is used only to attribute the finding to a file (the plan JSON
// itself; findings here have no line number in .tf source).
func (ConfirmedReplaceRule) Check(planPath string, changes []planjson.ResourceChange, aws *schema.AWS) []report.Finding {
	var findings []report.Finding

	for _, rc := range changes {
		critical := aws.CriticalStatefulResources[rc.Type]

		switch {
		case rc.Change.IsDestroyOnly():
			if !critical {
				continue
			}
			findings = append(findings, report.Finding{
				File:     planPath,
				Line:     1,
				Category: report.CategoryConfirmedReplace,
				Severity: report.SeverityCritical,
				Resource: rc.Address,
				Message: fmt.Sprintf(
					"terraform plan confirms %s will be DESTROYED with no replacement — this is a stateful/critical resource type; verify this is intentional before merging",
					rc.Type),
			})
		case rc.Change.IsReplace():
			severity := report.SeverityHigh
			if critical {
				severity = report.SeverityCritical
			}
			findings = append(findings, report.Finding{
				File:     planPath,
				Line:     1,
				Category: report.CategoryConfirmedReplace,
				Severity: severity,
				Resource: rc.Address,
				Message: fmt.Sprintf(
					"terraform plan confirms %s will be destroyed and recreated (replace) — data loss risk if this resource holds state",
					rc.Type),
			})
		}
	}

	return findings
}
