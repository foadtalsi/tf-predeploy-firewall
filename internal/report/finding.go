// Package report defines findings produced by the rule engine and renders
// them into a PR comment.
package report

import "strings"

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
	CategoryCostImpact       Category = "cost_impact"
)

// Finding is a single risk detected in a Terraform diff.
type Finding struct {
	File     string
	Line     int
	Category Category
	Severity Severity
	Resource string // "type.name" address, for context
	Message  string

	// Suggestion is an optional, mechanically-generated HCL snippet showing
	// how to fix the finding — not a computed byte-range patch against the
	// real file (this tool never has write access to the repo), just a
	// snippet the author can paste in. Populated only for categories where
	// a safe, generic fix exists; empty otherwise.
	Suggestion string

	// Fix, when set, is the same fix expressed as an exact line replacement,
	// which is what GitHub's one-click "Commit suggestion" button needs.
	// See Fix's doc comment for why this is a separate, much rarer field
	// than Suggestion.
	Fix *Fix

	// Waived, when true, excludes this finding from the blocking decision
	// and from SARIF output — an admin accepted this specific finding
	// (matched by category+resource+file, via the control plane's
	// per-finding waivers, Starter+) with WaiverNote as the justification.
	// It still appears in the PR comment, in its own section, so a waived
	// finding never just silently vanishes from the record.
	Waived     bool
	WaiverNote string
}

// Fix is an exactly-applicable replacement for lines [StartLine, EndLine] of
// the finding's file.
//
// It is deliberately narrower than Suggestion. A Suggestion is prose-adjacent:
// a snippet a human reads and adapts, free to reference a variable that
// doesn't exist yet or to show two edits in two places. A Fix is the literal
// text those lines must become, because GitHub renders it as a `suggestion`
// block whose "Commit suggestion" button writes it into the branch unread.
// Anything less than byte-exact would commit broken HCL on someone's behalf.
//
// So a rule only sets Fix when it can name the replacement with certainty:
// the value is written inline (not reached through a variable it can't
// rewrite), it occupies whole lines, and the generic fix is unambiguous.
// Every other finding still gets its Suggestion in the summary comment. A
// missing Fix is the normal case, not a gap.
type Fix struct {
	// StartLine and EndLine are inclusive, 1-based, and refer to the file
	// as it exists at the PR's head.
	StartLine int
	EndLine   int

	// Lines is the replacement content, one entry per line, already
	// indented to match the code it replaces. An empty slice deletes the
	// range.
	Lines []string

	// Note is optional context rendered beneath the suggestion — used when
	// applying the fix is correct but not sufficient on its own, e.g.
	// swapping a hardcoded password for `var.x` also requires declaring
	// `variable "x"` elsewhere in the module. Terraform fails loudly on the
	// undeclared variable, so the half-applied state is safe; saying so up
	// front is what stops it being a surprise.
	Note string
}

// Text renders the replacement lines as they would appear in the file.
func (f *Fix) Text() string {
	if f == nil {
		return ""
	}
	return strings.Join(f.Lines, "\n")
}
