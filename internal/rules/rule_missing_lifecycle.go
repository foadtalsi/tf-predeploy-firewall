package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
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
		// prevent_destroy guards a managed resource. Modules and data sources
		// have nothing for it to protect.
		if res.Kind != parser.KindResource {
			continue
		}
		if !aws.IsCritical(res.Type) {
			continue
		}

		if res.PreventDestroyValue != nil && *res.PreventDestroyValue {
			continue // properly protected
		}

		line := res.DefRange.Start.Line
		var detail, suggestion string
		var fix *report.Fix

		switch {
		case res.HasLifecycleBlock && res.PreventDestroyValue != nil && !*res.PreventDestroyValue:
			// lifecycle block exists but prevent_destroy is explicitly false
			line = res.PreventDestroyRange.Start.Line
			detail = fmt.Sprintf("%s explicitly sets prevent_destroy = false — remove this or set it to true to protect against accidental deletion", res.Type)
			suggestion = "  prevent_destroy = true"
			// Flipping one literal in place: the narrowest fix there is.
			if s, e, lines, ok := replaceAttrLine(in.HeadSource, res.PreventDestroyRange, "prevent_destroy", "prevent_destroy = true"); ok {
				fix = &report.Fix{StartLine: s, EndLine: e, Lines: lines}
			}

		case res.HasLifecycleBlock && res.PreventDestroyValue == nil:
			// lifecycle block exists but prevent_destroy is absent from it
			detail = fmt.Sprintf("%s has a lifecycle block but is missing prevent_destroy = true — add it to guard against accidental deletion", res.Type)
			suggestion = "  prevent_destroy = true"
			if s, e, lines, ok := insertIntoBlock(in.HeadSource, res.LifecycleRange, "prevent_destroy = true"); ok {
				fix = &report.Fix{StartLine: s, EndLine: e, Lines: lines}
			}

		default:
			// no lifecycle block at all
			detail = fmt.Sprintf("%s is a stateful/critical resource with no lifecycle { prevent_destroy = true } guard", res.Type)
			suggestion = "lifecycle {\n  prevent_destroy = true\n}"
			// The block goes just inside the resource header. Anywhere in the
			// body would be equally valid HCL, but the header is the one line
			// guaranteed to exist and to be unambiguous.
			if s, e, lines, ok := insertIntoBlock(in.HeadSource, res.DefRange,
				"lifecycle {", "  prevent_destroy = true", "}"); ok {
				fix = &report.Fix{StartLine: s, EndLine: e, Lines: lines}
			}
		}

		findings = append(findings, report.Finding{
			File:       in.Path,
			Line:       line,
			Category:   report.CategoryMissingLifecycle,
			Severity:   report.SeverityMedium,
			Resource:   res.Address(),
			Message:    detail,
			Suggestion: suggestion,
			Fix:        fix,
		})
	}

	return findings
}
