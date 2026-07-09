package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// UnknownAttributeRule (category a) flags attributes that aren't part of
// the known schema for a resource type — a common signature of AI
// hallucination (an attribute that "sounds right" but doesn't exist).
//
// Only resource types present in schema.AWS.ResourceSchemas are checked;
// unmapped types are skipped to avoid false positives on real-but-uncurated
// attributes.
type UnknownAttributeRule struct{}

func (UnknownAttributeRule) Check(in FileInput, aws *schema.AWS) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		resSchema, known := aws.ResourceSchemas[res.Type]
		if !known {
			continue
		}

		// --- Top-level attributes ---
		allowedTop := toSet(resSchema.TopLevel)
		for name, attr := range res.Attributes {
			if allowedTop[name] {
				continue
			}
			findings = append(findings, report.Finding{
				File:     in.Path,
				Line:     attr.Range.Start.Line,
				Category: report.CategoryUnknownAttribute,
				Severity: report.SeverityHigh,
				Resource: res.Address(),
				Message: fmt.Sprintf(
					"attribute %q is not a known argument of %s — likely hallucinated or deprecated; verify against the provider docs",
					name, res.Type),
			})
		}

		// --- Nested block attributes ---
		// Only validate block types that are explicitly listed in the schema;
		// uncurated block types (dynamic, provisioner, …) are skipped.
		for _, blk := range res.Blocks {
			allowedAttrs, blockKnown := resSchema.NestedBlocks[blk.Type]
			if !blockKnown {
				continue
			}
			allowedBlkSet := toSet(allowedAttrs)
			for name, attr := range blk.Attributes {
				if allowedBlkSet[name] {
					continue
				}
				findings = append(findings, report.Finding{
					File:     in.Path,
					Line:     attr.Range.Start.Line,
					Category: report.CategoryUnknownAttribute,
					Severity: report.SeverityHigh,
					Resource: res.Address(),
					Message: fmt.Sprintf(
						"attribute %q inside %s block is not a known argument — likely hallucinated or deprecated; verify against the provider docs",
						name, blk.Type),
				})
			}
		}
	}

	return findings
}

func toSet(list []string) map[string]bool {
	s := make(map[string]bool, len(list))
	for _, v := range list {
		s[v] = true
	}
	return s
}
