package report

import (
	"fmt"
	"sort"
	"strings"
)

// Marker delimits the tool's comment so subsequent runs can find and edit
// it instead of posting a new comment on every push.
const Marker = "<!-- tf-predeploy-firewall:report -->"

var severityEmoji = map[Severity]string{
	SeverityLow:      "🔵",
	SeverityMedium:   "🟡",
	SeverityHigh:     "🟠",
	SeverityCritical: "🔴",
}

var categoryLabel = map[Category]string{
	CategoryUnknownAttribute: "Unknown/hallucinated attribute",
	CategoryTutorialPattern:  "Tutorial-copy pattern",
	CategoryForceNewChange:   "ForceNew change on stateful resource",
	CategoryMissingLifecycle: "Missing prevent_destroy",
	CategoryConfirmedReplace: "Confirmed destroy/replace (from terraform plan)",
	CategoryUnexpectedDrift:  "Unexpected drift (from terraform plan)",
	CategoryLargeBlastRadius: "Large blast radius (from terraform plan)",
}

// RenderMarkdown builds the full PR comment body for a set of findings.
// blocked indicates whether the configured severity threshold was breached.
func RenderMarkdown(findings []Finding, threshold Severity, blocked bool) string {
	var b strings.Builder
	b.WriteString(Marker + "\n")
	b.WriteString("## TF Pre-Deploy Firewall\n\n")

	if len(findings) == 0 {
		b.WriteString("No risk patterns detected in the changed Terraform files. ✅\n")
		return b.String()
	}

	sorted := make([]Finding, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].File != sorted[j].File {
			return sorted[i].File < sorted[j].File
		}
		return sorted[i].Line < sorted[j].Line
	})

	if blocked {
		fmt.Fprintf(&b, "🚫 **Merge blocked** — findings at or above `%s` severity (threshold: `%s`).\n\n", highestSeverity(sorted), threshold)
	} else {
		fmt.Fprintf(&b, "⚠️ %d finding(s), none reach the `%s` blocking threshold.\n\n", len(sorted), threshold)
	}

	b.WriteString("| Severity | File | Line | Category | Resource | Detail |\n")
	b.WriteString("|---|---|---|---|---|---|\n")
	for _, f := range sorted {
		fmt.Fprintf(&b, "| %s %s | `%s` | %d | %s | `%s` | %s |\n",
			severityEmoji[f.Severity], f.Severity, f.File, f.Line, categoryLabel[f.Category], f.Resource, f.Message)
	}

	return b.String()
}

func highestSeverity(findings []Finding) Severity {
	highest := SeverityLow
	for _, f := range findings {
		if f.Severity.AtLeast(highest) {
			highest = f.Severity
		}
	}
	return highest
}
