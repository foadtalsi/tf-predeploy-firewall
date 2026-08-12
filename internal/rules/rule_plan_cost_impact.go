package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// CostImpactRule estimates the monthly cost DELTA a plan will cause and
// flags it when it crosses a configurable threshold. Costs come from the
// curated aws_pricing.json — deliberately coarse, region-agnostic
// estimates: the goal is an early "this PR meaningfully raises the bill"
// warning in review, not a billing-accurate quote (that's what tools like
// Infracost or the AWS calculator are for, after merge).
//
// Delta model, per managed resource in the plan:
//   - create:            +cost(after)
//   - destroy:           -cost(before)
//   - replace:           cost(after) - cost(before)  (usually 0 unless the
//     pricing-driving attribute changed, e.g. instance_type upsizing)
//   - update:            cost(after) - cost(before)
//
// Resource types absent from the pricing map contribute $0 — unknown types
// are ignored rather than guessed at, consistent with every other curated
// data file in this project.
type CostImpactRule struct {
	// ThresholdUSD is the monthly cost increase (in USD) that triggers a
	// finding. Zero or negative disables the rule.
	ThresholdUSD float64
}

// resourceCostDelta is one resource's contribution, kept for the message.
type resourceCostDelta struct {
	address string
	delta   float64
}

func (r CostImpactRule) Check(planPath string, changes []planjson.ResourceChange, aws *schema.AWS) []report.Finding {
	if r.ThresholdUSD <= 0 {
		return nil
	}

	var total float64
	var deltas []resourceCostDelta

	for _, rc := range changes {
		if !rc.IsManaged() {
			continue
		}
		spec, priced := aws.Pricing[rc.Type]
		if !priced {
			continue
		}

		beforeCost := costOfState(spec, rc.Change.Before)
		afterCost := costOfState(spec, rc.Change.After)

		var delta float64
		switch {
		case rc.Change.IsDestroyOnly():
			delta = -beforeCost
		case rc.Change.IsNoOp():
			continue
		default:
			// create (before nil -> beforeCost 0), replace, or update: the
			// generic after-minus-before form covers all three.
			delta = afterCost - beforeCost
		}
		if delta == 0 {
			continue
		}
		total += delta
		deltas = append(deltas, resourceCostDelta{address: rc.Address, delta: delta})
	}

	if total < r.ThresholdUSD {
		return nil
	}

	severity := report.SeverityMedium
	if total >= r.ThresholdUSD*5 {
		severity = report.SeverityHigh
	}

	return []report.Finding{{
		File:     planPath,
		Line:     1,
		Category: report.CategoryCostImpact,
		Severity: severity,
		Resource: fmt.Sprintf("+$%.0f/month (estimated)", total),
		Message: fmt.Sprintf(
			"this plan increases the estimated AWS bill by ~$%.0f/month (threshold: $%.0f) — rough on-demand estimate, not a quote. Top contributors: %s",
			total, r.ThresholdUSD, topContributors(deltas, 5)),
	}}
}

// costOfState estimates the monthly cost of one side (before/after) of a
// resource change. A nil state (resource doesn't exist on that side) is $0.
func costOfState(spec *schema.PricingSpec, state map[string]interface{}) float64 {
	if state == nil {
		return 0
	}
	attrValue := ""
	if spec.Attribute != "" {
		if v, ok := state[spec.Attribute].(string); ok {
			attrValue = v
		}
	}
	return spec.MonthlyCost(attrValue)
}

// topContributors formats the n largest positive contributors for the
// finding message, so the reviewer immediately sees WHAT is expensive.
func topContributors(deltas []resourceCostDelta, n int) string {
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].delta > deltas[j].delta })
	var parts []string
	for _, d := range deltas {
		if d.delta <= 0 || len(parts) >= n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s (+$%.0f)", d.address, d.delta))
	}
	if len(parts) == 0 {
		return "(none individually significant)"
	}
	return strings.Join(parts, ", ")
}
