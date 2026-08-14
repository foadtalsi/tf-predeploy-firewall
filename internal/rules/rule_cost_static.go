package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// StaticCostRule estimates the monthly cost of resources straight from the
// .tf diff, using the same per-type pricing the plan-based CostImpactRule
// uses — for the majority of repos that never wire a plan JSON into the
// scan. Supplying one is strictly better (it sees counts, for_each and
// computed values), which is why main only runs this rule when no plan is
// given: the same PR must not be billed twice by two estimators that could
// disagree.
//
// What a source-only estimate can honestly claim, and nothing more:
//
//   - A NEW resource of a priced type costs about its list price. Reported
//     when that clears the threshold.
//   - A CHANGED pricing-driving attribute (instance_type and friends) moves
//     the estimate from A to B. Reported when the increase clears the
//     threshold — decreases are never findings, spending less needs no gate.
//
// count/for_each multipliers are deliberately ignored rather than guessed
// at: understating a fleet's cost is bad, but inventing a number is worse.
type StaticCostRule struct {
	// ThresholdUSD is the estimated monthly increase that triggers a
	// finding. Zero disables the rule (it shouldn't be constructed at all
	// then; the guard is defence in depth).
	ThresholdUSD float64
}

func (r StaticCostRule) Check(in FileInput, kb *schema.KnowledgeBase) []report.Finding {
	if r.ThresholdUSD <= 0 {
		return nil
	}

	var findings []report.Finding
	for _, res := range in.HeadResources {
		if res.Kind != parser.KindResource {
			continue
		}
		spec, priced := kb.PricingFor(res.Type)
		if !priced {
			continue
		}

		attrValue := pricingAttrValue(res, spec)
		newCost := spec.MonthlyCost(attrValue)

		base, existedBefore := in.BaseResources[res.Address()]
		if !existedBefore {
			if newCost >= r.ThresholdUSD {
				findings = append(findings, report.Finding{
					File:     in.Path,
					Line:     res.DefRange.Start.Line,
					Category: report.CategoryCostImpact,
					Severity: report.SeverityMedium,
					Resource: res.Address(),
					Message: fmt.Sprintf(
						"new %s adds an estimated $%.0f/month%s — static list-price estimate, not a quote; count/for_each not included",
						res.Type, newCost, describePricingDriver(spec, attrValue)),
				})
			}
			continue
		}

		oldCost := spec.MonthlyCost(pricingAttrValue(base, spec))
		if newCost-oldCost >= r.ThresholdUSD {
			findings = append(findings, report.Finding{
				File:     in.Path,
				Line:     pricingAttrLine(res, spec),
				Category: report.CategoryCostImpact,
				Severity: report.SeverityMedium,
				Resource: res.Address(),
				Message: fmt.Sprintf(
					"%s estimated cost rises from $%.0f to $%.0f/month%s — static list-price estimate, not a quote",
					res.Type, oldCost, newCost, describePricingDriver(spec, attrValue)),
			})
		}
	}
	return findings
}

// pricingAttrValue reads the pricing-driving attribute's literal value, ""
// when there is none or it isn't statically known — MonthlyCost then falls
// back to the type's default figure, which is the honest answer for a size
// the scanner can't see.
func pricingAttrValue(res *parser.Resource, spec *schema.PricingSpec) string {
	if spec.Attribute == "" {
		return ""
	}
	if attr, ok := res.Attributes[spec.Attribute]; ok && attr.IsLiteral {
		return attr.RawValue
	}
	return ""
}

// pricingAttrLine anchors a cost-change finding on the attribute that
// changed the number, falling back to the resource header.
func pricingAttrLine(res *parser.Resource, spec *schema.PricingSpec) int {
	if spec.Attribute != "" {
		if attr, ok := res.Attributes[spec.Attribute]; ok {
			return attr.Range.Start.Line
		}
	}
	return res.DefRange.Start.Line
}

func describePricingDriver(spec *schema.PricingSpec, attrValue string) string {
	if spec.Attribute == "" || attrValue == "" {
		return ""
	}
	return fmt.Sprintf(" (%s = %q)", spec.Attribute, attrValue)
}
