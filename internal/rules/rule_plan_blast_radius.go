package rules

import (
	"fmt"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/planjson"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// BlastRadiusRule flags a plan whose number of destroy/replace actions
// exceeds a configurable threshold — a signal that something (a module
// refactor, a provider upgrade, a moved resource without `moved` blocks)
// is about to touch far more infrastructure than a typical PR should.
type BlastRadiusRule struct {
	// Threshold is the number of destroy+replace actions that triggers the
	// finding. Zero or negative disables the rule.
	Threshold int
}

func (r BlastRadiusRule) Check(planPath string, changes []planjson.ResourceChange, aws *schema.AWS) []report.Finding {
	if r.Threshold <= 0 {
		return nil
	}

	var destructive []string
	for _, rc := range changes {
		if !rc.IsManaged() {
			continue
		}
		if rc.Change.IsDestroyOnly() || rc.Change.IsReplace() {
			destructive = append(destructive, rc.Address)
		}
	}

	if len(destructive) < r.Threshold {
		return nil
	}

	severity := report.SeverityHigh
	if len(destructive) >= r.Threshold*2 {
		severity = report.SeverityCritical
	}

	return []report.Finding{{
		File:     planPath,
		Line:     1,
		Category: report.CategoryLargeBlastRadius,
		Severity: severity,
		Resource: fmt.Sprintf("%d resources", len(destructive)),
		Message: fmt.Sprintf(
			"this plan destroys or replaces %d resources (threshold: %d) — blast radius is unusually large for a single PR; double check this isn't an unintended module move or provider upgrade side-effect. Affected: %s",
			len(destructive), r.Threshold, joinTruncated(destructive, 10)),
	}}
}

func joinTruncated(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(items[:max], ", "), len(items)-max)
}
