package report

import (
	"strings"
	"testing"
)

func TestRenderMarkdown_NoFindings(t *testing.T) {
	out := RenderMarkdown(nil, SeverityHigh, false)
	if !strings.Contains(out, Marker) {
		t.Error("expected HTML marker to be present")
	}
	if !strings.Contains(out, "No risk patterns") {
		t.Error("expected 'No risk patterns' message for empty findings")
	}
}

func TestRenderMarkdown_BlockedMessage(t *testing.T) {
	findings := []Finding{
		{File: "main.tf", Line: 3, Category: CategoryTutorialPattern, Severity: SeverityCritical, Resource: "aws_db_instance.x", Message: "password in plaintext"},
	}
	out := RenderMarkdown(findings, SeverityHigh, true)
	if !strings.Contains(out, "Merge blocked") {
		t.Error("expected 'Merge blocked' when blocked=true")
	}
	if !strings.Contains(out, "main.tf") {
		t.Error("expected file name in output")
	}
}

func TestRenderMarkdown_NotBlocked(t *testing.T) {
	findings := []Finding{
		{File: "main.tf", Line: 5, Category: CategoryMissingLifecycle, Severity: SeverityMedium, Resource: "aws_db_instance.y", Message: "no prevent_destroy"},
	}
	out := RenderMarkdown(findings, SeverityHigh, false)
	if strings.Contains(out, "Merge blocked") {
		t.Error("must not say 'Merge blocked' when blocked=false")
	}
	if !strings.Contains(out, "⚠️") {
		t.Error("expected warning emoji for non-blocking findings")
	}
}

func TestRenderMarkdown_SuggestionRenderedAsCollapsibleCodeBlock(t *testing.T) {
	findings := []Finding{
		{File: "main.tf", Line: 5, Category: CategoryMissingLifecycle, Severity: SeverityMedium, Resource: "aws_db_instance.y", Message: "no prevent_destroy"},
		{File: "main.tf", Line: 9, Category: CategoryMissingLifecycle, Severity: SeverityMedium, Resource: "aws_db_instance.z", Message: "no prevent_destroy",
			Suggestion: "lifecycle {\n  prevent_destroy = true\n}"},
	}
	out := RenderMarkdown(findings, SeverityHigh, false)

	if !strings.Contains(out, "### Suggested fixes") {
		t.Error("expected a Suggested fixes section when at least one finding has a suggestion")
	}
	if !strings.Contains(out, "```hcl") || !strings.Contains(out, "prevent_destroy = true") {
		t.Error("expected the suggestion rendered as a fenced hcl code block")
	}
	if !strings.Contains(out, "<details>") {
		t.Error("expected the suggestion wrapped in a collapsible <details> block")
	}
	if strings.Count(out, "<details>") != 1 {
		t.Errorf("expected exactly 1 suggestion block (only aws_db_instance.z has one), got %d", strings.Count(out, "<details>"))
	}
}

func TestRenderMarkdown_NoSuggestionSectionWhenNoneHaveSuggestions(t *testing.T) {
	findings := []Finding{
		{File: "main.tf", Line: 5, Category: CategoryUnknownAttribute, Severity: SeverityMedium, Resource: "aws_instance.x", Message: "unknown attr"},
	}
	out := RenderMarkdown(findings, SeverityHigh, false)
	if strings.Contains(out, "Suggested fixes") {
		t.Error("did not expect a Suggested fixes section when no finding has a suggestion")
	}
}

func TestRenderMarkdown_WaivedFindingExcludedFromTableAndBlocking(t *testing.T) {
	findings := []Finding{
		{File: "main.tf", Line: 3, Category: CategoryMissingLifecycle, Severity: SeverityCritical, Resource: "aws_db_instance.legacy", Message: "no prevent_destroy",
			Waived: true, WaiverNote: "legacy repo, ticketed for cleanup in INFRA-42"},
	}
	// blocked=false here simulates the caller (cmd/scanner) having already
	// excluded the waived finding before computing the block decision —
	// RenderMarkdown itself doesn't recompute blocked, it just must not
	// contradict it by putting a waived finding in the blocking table.
	out := RenderMarkdown(findings, SeverityHigh, false)
	if strings.Contains(out, "Merge blocked") {
		t.Error("a fully-waived finding set must not say 'Merge blocked'")
	}
	if !strings.Contains(out, "No blocking findings") {
		t.Error("expected the 'no blocking findings, N waived' message")
	}
	if !strings.Contains(out, "INFRA-42") {
		t.Error("expected the waiver justification to appear in the waived section")
	}
	// The waived finding's row must appear once (in the waived <details>
	// section), not in the active findings table above it.
	if strings.Count(out, "aws_db_instance.legacy") != 1 {
		t.Errorf("expected the waived finding to appear exactly once, got %d occurrences", strings.Count(out, "aws_db_instance.legacy"))
	}
}

func TestRenderMarkdown_MixedActiveAndWaivedFindings(t *testing.T) {
	findings := []Finding{
		{File: "main.tf", Line: 3, Category: CategoryTutorialPattern, Severity: SeverityCritical, Resource: "aws_db_instance.x", Message: "password in plaintext"},
		{File: "main.tf", Line: 8, Category: CategoryMissingLifecycle, Severity: SeverityMedium, Resource: "aws_db_instance.y", Message: "no prevent_destroy",
			Waived: true, WaiverNote: "accepted, sandbox repo"},
	}
	out := RenderMarkdown(findings, SeverityHigh, true)
	if !strings.Contains(out, "Merge blocked") {
		t.Error("expected 'Merge blocked' — the active critical finding alone breaches the threshold")
	}
	if !strings.Contains(out, "1 waived finding") {
		t.Error("expected the waived-findings section header to mention exactly 1 waived finding")
	}
	if !strings.Contains(out, "accepted, sandbox repo") {
		t.Error("expected the waiver justification for the waived finding")
	}
}

func TestSeverityAtLeast(t *testing.T) {
	cases := []struct {
		s, other Severity
		want     bool
	}{
		{SeverityCritical, SeverityHigh, true},
		{SeverityHigh, SeverityHigh, true},
		{SeverityMedium, SeverityHigh, false},
		{SeverityLow, SeverityCritical, false},
	}
	for _, c := range cases {
		got := c.s.AtLeast(c.other)
		if got != c.want {
			t.Errorf("%s.AtLeast(%s) = %v, want %v", c.s, c.other, got, c.want)
		}
	}
}
