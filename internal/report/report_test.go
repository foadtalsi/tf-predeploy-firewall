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
