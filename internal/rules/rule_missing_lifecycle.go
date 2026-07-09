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
		var detail string
		switch {
		case res.HasLifecycleBlock && res.PreventDestroyValue != nil && !*res.PreventDestroyValue:
			// lifecycle block exists but prevent_destroy is explicitly false
			line = res.PreventDestroyRange.Start.Line
			detail = fmt.Sprintf("%s explicitly sets prevent_destroy = false — remove this or set it to true to protect against accidental deletion", res.Type)
		case res.HasLifecycleBlock && res.PreventDestroyValue == nil:
			// lifecycle block exists but prevent_destroy is absent from it
			detail = fmt.Sprintf("%s has a lifecycle block but is missing prevent_destroy = true — add it to guard against accidental deletion", res.Type)
		default:
			// no lifecycle block at all
			detail = fmt.Sprintf("%s is a stateful/critical resource with no lifecycle { prevent_destroy = true } guard", res.Type)
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
