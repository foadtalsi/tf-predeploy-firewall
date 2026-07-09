package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
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
			continue
		}

		spec, known := aws.ForceNewAttrs[res.Type]
		if !known {
			continue
		}

		severity := report.SeverityHigh
		if aws.CriticalStatefulResources[res.Type] {
			severity = report.SeverityCritical
		}

		// Top-level attributes.
		for _, attrName := range spec.TopLevel {
			if f, ok := compareAttr(in.Path, res.Address(), res.Type, attrName, "",
				res.Attributes[attrName], base.Attributes[attrName], severity); ok {
				findings = append(findings, f)
			}
		}

		// Attributes inside nested blocks (e.g. root_block_device, ebs_block_device).
		for blockType, forceNewAttrs := range spec.NestedBlocks {
			headBlk := findBlock(res.Blocks, blockType)
			baseBlk := findBlock(base.Blocks, blockType)
			if headBlk == nil || baseBlk == nil {
				continue // block absent in one revision; not a value change
			}
			for _, attrName := range forceNewAttrs {
				if f, ok := compareAttr(in.Path, res.Address(), res.Type,
					attrName, blockType,
					headBlk.Attributes[attrName], baseBlk.Attributes[attrName], severity); ok {
					findings = append(findings, f)
				}
			}
		}
	}

	return findings
}

func compareAttr(path, resource, resType, attrName, blockContext string,
	head, base *parser.Attribute, severity report.Severity,
) (report.Finding, bool) {
	if head == nil || base == nil {
		return report.Finding{}, false
	}
	// When both revisions have the attribute but one or both values reference a
	// variable/expression we can't resolve statically, emit a lower-severity
	// informational finding instead of silently skipping — the user should
	// verify the value won't change at plan time.
	if !head.IsLiteral || !base.IsLiteral {
		location := attrName
		if blockContext != "" {
			location = blockContext + "." + attrName
		}
		return report.Finding{
			File:     path,
			Line:     head.Range.Start.Line,
			Category: report.CategoryForceNewChange,
			Severity: report.SeverityLow,
			Resource: resource,
			Message: fmt.Sprintf(
				"%q is a ForceNew attribute on %s and uses a non-literal expression — verify the resolved value won't change at plan time (would trigger destroy+recreate)",
				location, resType),
		}, true
	}
	if head.RawValue == base.RawValue {
		return report.Finding{}, false
	}

	location := attrName
	if blockContext != "" {
		location = blockContext + "." + attrName
	}

	return report.Finding{
		File:     path,
		Line:     head.Range.Start.Line,
		Category: report.CategoryForceNewChange,
		Severity: severity,
		Resource: resource,
		Message: fmt.Sprintf(
			"%q changed from %q to %q — this attribute is ForceNew on %s and will destroy + recreate the resource on apply",
			location, base.RawValue, head.RawValue, resType),
	}, true
}

func findBlock(blocks []*parser.NestedBlock, blockType string) *parser.NestedBlock {
	for _, b := range blocks {
		if b.Type == blockType {
			return b
		}
	}
	return nil
}
