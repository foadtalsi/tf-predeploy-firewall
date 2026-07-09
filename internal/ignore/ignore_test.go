package ignore

import (
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

const src = `
resource "aws_db_instance" "x" {
  password   = "changeme"  # tf-firewall-ignore: tutorial_pattern
  identifier = "example"
  # tf-firewall-ignore: missing_lifecycle
  engine = "postgres"
}
`

func TestParseComments_SameLine(t *testing.T) {
	m := ParseComments([]byte(src))
	// "password" is on line 3; directive is on the same line -> suppresses line 3
	if !m[3][report.CategoryTutorialPattern] {
		t.Error("expected tutorial_pattern suppressed on line 3 (same-line directive)")
	}
}

func TestParseComments_LineAbove(t *testing.T) {
	m := ParseComments([]byte(src))
	// directive on line 5 -> suppresses line 5 AND line 6 (engine = "postgres")
	if !m[6][report.CategoryMissingLifecycle] {
		t.Error("expected missing_lifecycle suppressed on line 6 (directive on line above)")
	}
}

func TestApply_InlineIgnore(t *testing.T) {
	findings := []report.Finding{
		{File: "main.tf", Line: 3, Category: report.CategoryTutorialPattern, Severity: report.SeverityCritical},
		{File: "main.tf", Line: 4, Category: report.CategoryTutorialPattern, Severity: report.SeverityLow},
	}
	inlineByFile := map[string]map[int]map[report.Category]bool{
		"main.tf": {
			3: {report.CategoryTutorialPattern: true},
		},
	}
	out := Apply(findings, inlineByFile, nil)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding after apply, got %d", len(out))
	}
	if out[0].Line != 4 {
		t.Errorf("expected surviving finding on line 4, got line %d", out[0].Line)
	}
}

func TestApply_GlobalIgnore(t *testing.T) {
	findings := []report.Finding{
		{File: "main.tf", Line: 1, Category: report.CategoryMissingLifecycle, Severity: report.SeverityMedium},
		{File: "main.tf", Line: 2, Category: report.CategoryForceNewChange, Severity: report.SeverityHigh},
	}
	out := Apply(findings, nil, []report.Category{report.CategoryMissingLifecycle})
	if len(out) != 1 || out[0].Category != report.CategoryForceNewChange {
		t.Errorf("expected only force_new_change to survive, got %+v", out)
	}
}

func TestApply_AllKeyword(t *testing.T) {
	findings := []report.Finding{
		{File: "a.tf", Line: 5, Category: report.CategoryUnknownAttribute, Severity: report.SeverityHigh},
		{File: "a.tf", Line: 5, Category: report.CategoryTutorialPattern, Severity: report.SeverityLow},
	}
	inlineByFile := map[string]map[int]map[report.Category]bool{
		"a.tf": {5: {report.Category("all"): true}},
	}
	out := Apply(findings, inlineByFile, nil)
	if len(out) != 0 {
		t.Errorf("expected all findings suppressed by 'all' keyword, got %d", len(out))
	}
}
