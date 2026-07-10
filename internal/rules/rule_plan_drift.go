package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// DriftRule flags a plan update where a sensitive attribute's value is
// changing even though this PR's own .tf diff never touched it. That means
// the change is coming from somewhere else: a manually-edited default, a
// provider version bump shifting a computed default, or state that already
// drifted from a prior out-of-band change. Either way, the PR author should
// know their apply will do more than what they wrote.
//
// Scope is deliberately narrow for this first increment: only resources
// present in aws.ForceNewAttrs (i.e. attributes we already know matter
// enough to be curated), and only pure in-place updates — a replace or
// destroy is already covered by ConfirmedReplaceRule and would just be
// noise here.
type DriftRule struct{}

// ChangedAttrs maps resource address -> attribute keys this PR's .tf diff
// actually touched (from rules.Result.ChangedAttrs).
func (DriftRule) Check(planPath string, changes []planjson.ResourceChange, changedAttrs map[string]map[ChangedAttrKey]bool, aws *schema.AWS) []report.Finding {
	var findings []report.Finding

	for _, rc := range changes {
		if !rc.Change.IsPureUpdate() {
			continue
		}
		spec, known := aws.ForceNewAttrs[rc.Type]
		if !known || len(spec.TopLevel) == 0 {
			continue
		}

		touchedByPR := changedAttrs[rc.Address]

		for _, attrName := range spec.TopLevel {
			before, hasBefore := rc.Change.Before[attrName]
			after, hasAfter := rc.Change.After[attrName]
			if !hasBefore || !hasAfter {
				continue
			}
			if fmt.Sprint(before) == fmt.Sprint(after) {
				continue
			}
			if touchedByPR != nil && touchedByPR[ChangedAttrKey(attrName)] {
				continue // this PR's diff explains the change; not drift
			}

			findings = append(findings, report.Finding{
				File:     planPath,
				Line:     1,
				Category: report.CategoryUnexpectedDrift,
				Severity: report.SeverityMedium,
				Resource: rc.Address,
				Message: fmt.Sprintf(
					"terraform plan shows %q changing from %v to %v on %s, but this PR's .tf diff doesn't touch that attribute — the change is coming from elsewhere (state drift, a provider default, or an out-of-band edit); verify before merging",
					attrName, before, after, rc.Type),
			})
		}
	}

	return findings
}
