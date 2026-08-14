package report

import (
	"fmt"
	"sort"
	"strings"
)

const customCategoryPrefix = "custom:"

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
	CategoryUnpinnedVersion:  "Unpinned module or provider version",
	CategoryTutorialPattern:  "Tutorial-copy pattern",
	CategoryForceNewChange:   "ForceNew change on stateful resource",
	CategoryMissingLifecycle: "Missing prevent_destroy",
	CategoryConfirmedReplace: "Confirmed destroy/replace (from terraform plan)",
	CategoryUnexpectedDrift:  "Unexpected drift (from terraform plan)",
	CategoryLargeBlastRadius: "Large blast radius (from terraform plan)",
	CategoryCostImpact:       "Estimated cost impact",
}

// RenderMarkdown builds the full PR comment body for a set of findings.
// blocked indicates whether the configured severity threshold was breached
// by the ACTIVE (non-waived) findings — a waived finding never contributes
// to blocked, but still appears in its own section below so accepting one
// is never silent.
func RenderMarkdown(findings []Finding, threshold Severity, blocked bool) string {
	var b strings.Builder
	b.WriteString(Marker + "\n")
	b.WriteString("## TF Pre-Deploy Firewall\n\n")

	var active, waived []Finding
	for _, f := range findings {
		if f.Waived {
			waived = append(waived, f)
		} else {
			active = append(active, f)
		}
	}

	if len(active) == 0 && len(waived) == 0 {
		b.WriteString("No risk patterns detected in the changed Terraform files. ✅\n")
		return b.String()
	}

	sort.Slice(active, func(i, j int) bool {
		if active[i].File != active[j].File {
			return active[i].File < active[j].File
		}
		return active[i].Line < active[j].Line
	})

	if len(active) == 0 {
		fmt.Fprintf(&b, "✅ No blocking findings — %d finding(s) previously accepted (see below).\n\n", len(waived))
	} else if blocked {
		fmt.Fprintf(&b, "🚫 **Merge blocked** — findings at or above `%s` severity (threshold: `%s`).\n\n", highestSeverity(active), threshold)
	} else {
		fmt.Fprintf(&b, "⚠️ %d finding(s), none reach the `%s` blocking threshold.\n\n", len(active), threshold)
	}

	if len(active) > 0 {
		b.WriteString("| Severity | File | Line | Category | Resource | Detail |\n")
		b.WriteString("|---|---|---|---|---|---|\n")
		for _, f := range active {
			fmt.Fprintf(&b, "| %s %s | `%s` | %d | %s | %s | %s |\n",
				severityEmoji[f.Severity], f.Severity, f.File, f.Line, categoryDisplay(f.Category), resourceCell(f), f.Message)
		}
	}

	renderSuggestions(&b, active)
	renderWaivers(&b, waived)

	return b.String()
}

// renderWaivers lists findings an admin accepted via the control plane
// (Starter+, GET /v1/waivers) — visible so a waiver is a documented
// decision, not a silent removal from the report.
func renderWaivers(b *strings.Builder, waived []Finding) {
	if len(waived) == 0 {
		return
	}
	sort.Slice(waived, func(i, j int) bool {
		if waived[i].File != waived[j].File {
			return waived[i].File < waived[j].File
		}
		return waived[i].Line < waived[j].Line
	})

	fmt.Fprintf(b, "\n<details><summary>%d accepted finding(s) — excluded from the block decision</summary>\n\n", len(waived))
	b.WriteString("| Severity | File | Line | Category | Resource | Detail | Accepted because |\n")
	b.WriteString("|---|---|---|---|---|---|---|\n")
	for _, f := range waived {
		fmt.Fprintf(b, "| %s %s | `%s` | %d | %s | %s | %s | %s |\n",
			severityEmoji[f.Severity], f.Severity, f.File, f.Line, categoryDisplay(f.Category), resourceCell(f), f.Message, f.WaiverNote)
	}
	b.WriteString("\n</details>\n")
}

// resourceCell renders the resource address, linked to the provider
// documentation for its type when one is known. The link rides on the
// address rather than taking a column of its own: a seventh column would
// cost every row width, on a table that is already wide, to carry the same
// word on every line.
func resourceCell(f Finding) string {
	if f.DocURL == "" {
		return "`" + f.Resource + "`"
	}
	return fmt.Sprintf("[`%s`](%s)", f.Resource, f.DocURL)
}

// renderSuggestions appends a collapsible "Suggested fixes" block per
// finding that has one — pasteable HCL, not a computed patch (this tool
// never has write access to the repo). Kept out of the main table since a
// multi-line code block doesn't fit inside a markdown table cell.
func renderSuggestions(b *strings.Builder, sorted []Finding) {
	var any bool
	for _, f := range sorted {
		if f.Suggestion != "" {
			any = true
			break
		}
	}
	if !any {
		return
	}

	b.WriteString("\n### Suggested fixes\n\n")
	for _, f := range sorted {
		if f.Suggestion == "" {
			continue
		}
		fmt.Fprintf(b, "<details><summary><code>%s</code> (%s:%d)</summary>\n\n```hcl\n%s\n```\n\n</details>\n\n",
			f.Resource, f.File, f.Line, f.Suggestion)
	}
}

// categoryDisplay labels a category for the PR comment. Custom rules
// (category "custom:<rule-id>", from internal/customrules) aren't in the
// built-in categoryLabel map — they're rendered as "Custom rule: <id>"
// instead of falling back to an empty string.
func categoryDisplay(c Category) string {
	if label, ok := categoryLabel[c]; ok {
		return label
	}
	if id, isCustom := strings.CutPrefix(string(c), customCategoryPrefix); isCustom {
		return "Custom rule: " + id
	}
	return string(c)
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
