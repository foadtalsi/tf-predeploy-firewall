package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// MissingLifecycleRule (category d) flags critical stateful resources
// (databases, volumes, etc.) that don't declare
// lifecycle { prevent_destroy = true }, leaving them exposed to accidental
// deletion via a careless apply.
type MissingLifecycleRule struct{}

func (MissingLifecycleRule) Check(in FileInput, aws *schema.AWS) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		if !aws.CriticalStatefulResources[res.Type] {
			continue
		}

		if res.PreventDestroyValue != nil && *res.PreventDestroyValue {
			continue // properly protected
		}

		line := res.DefRange.Start.Line
		detail := fmt.Sprintf("%s is a stateful/critical resource but has no lifecycle { prevent_destroy = true } guard", res.Type)
		if res.HasLifecycleBlock && res.PreventDestroyValue != nil && !*res.PreventDestroyValue {
			line = res.PreventDestroyRange.Start.Line
			detail = fmt.Sprintf("%s explicitly sets prevent_destroy = false on a stateful/critical resource", res.Type)
		}

		findings = append(findings, report.Finding{
			File:     in.Path,
			Line:     line,
			Category: report.CategoryMissingLifecycle,
			Severity: report.SeverityMedium,
			Resource: res.Address(),
			Message:  detail,
		})
	}

	return findings
}
