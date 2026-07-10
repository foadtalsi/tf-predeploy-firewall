// Package report defines findings produced by the rule engine and renders
// them into a PR comment.
package report

// Severity levels, ordered low to high.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var severityRank = map[Severity]int{
	SeverityLow:      0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// AtLeast reports whether s is at least as severe as other.
func (s Severity) AtLeast(other Severity) bool {
	return severityRank[s] >= severityRank[other]
}

// Category identifies which detection rule produced a finding.
type Category string

const (
	CategoryUnknownAttribute Category = "unknown_attribute"
	CategoryTutorialPattern  Category = "tutorial_pattern"
	CategoryForceNewChange   Category = "force_new_change"
	CategoryMissingLifecycle Category = "missing_lifecycle"

	// Phase 2 categories: require a `terraform show -json` plan supplied
	// via --plan-json. Unlike the categories above, these are derived from
	// Terraform's own diff engine, not a heuristic over the .tf source.
	CategoryConfirmedReplace Category = "confirmed_replace"
	CategoryUnexpectedDrift  Category = "unexpected_drift"
	CategoryLargeBlastRadius Category = "large_blast_radius"
)

// Finding is a single risk detected in a Terraform diff.
type Finding struct {
	File     string
	Line     int
	Category Category
	Severity Severity
	Resource string // "type.name" address, for context
	Message  string
}
