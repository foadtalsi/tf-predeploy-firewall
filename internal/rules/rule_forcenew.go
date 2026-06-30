package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// ForceNewChangeRule (category c) flags edits to attributes known to be
// ForceNew in the AWS provider schema, on a resource that already existed
// before this change. Without a plan or state we can't know what's
// actually deployed, but "this attribute changed on a pre-existing
// resource address" is a reliable proxy: applying it will destroy and
// recreate the resource.
type ForceNewChangeRule struct{}

func (ForceNewChangeRule) Check(in FileInput, aws *schema.AWS) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		base, existedBefore := in.BaseResources[res.Address()]
		if !existedBefore {
			continue // brand-new resource in this PR: nothing to "force replace" yet
		}

		forceNewAttrs, known := aws.ForceNewAttrs[res.Type]
		if !known {
			continue
		}

		for _, attrName := range forceNewAttrs {
			headAttr, headHas := res.Attributes[attrName]
			baseAttr, baseHas := base.Attributes[attrName]

			if !headHas || !baseHas {
				continue // attribute added/removed entirely; rule d / plain diff already surfaces that
			}
			if !headAttr.IsLiteral || !baseAttr.IsLiteral {
				continue // can't compare values we couldn't statically resolve
			}
			if headAttr.RawValue == baseAttr.RawValue {
				continue
			}

			severity := report.SeverityHigh
			if aws.CriticalStatefulResources[res.Type] {
				severity = report.SeverityCritical
			}

			findings = append(findings, report.Finding{
				File:     in.Path,
				Line:     headAttr.Range.Start.Line,
				Category: report.CategoryForceNewChange,
				Severity: severity,
				Resource: res.Address(),
				Message: fmt.Sprintf(
					"%q changed from %q to %q — this attribute is ForceNew on %s and will destroy + recreate the resource on apply",
					attrName, baseAttr.RawValue, headAttr.RawValue, res.Type),
			})
		}
	}

	return findings
}
