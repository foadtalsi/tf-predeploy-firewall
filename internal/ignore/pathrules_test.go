package ignore

import (
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func TestApplyPathRules_DoubleStarMatchesEntireSubtree(t *testing.T) {
	findings := []report.Finding{
		{File: "legacy/modules/rds/main.tf", Category: report.CategoryMissingLifecycle},
		{File: "prod/main.tf", Category: report.CategoryMissingLifecycle},
	}
	rules := []PathRule{{Pattern: "legacy/**"}}

	out := ApplyPathRules(findings, rules)
	if len(out) != 1 || out[0].File != "prod/main.tf" {
		t.Fatalf("expected only the prod finding to survive, got %#v", out)
	}
}

func TestApplyPathRules_ScopedToCategoriesWhenSet(t *testing.T) {
	findings := []report.Finding{
		{File: "sandbox/main.tf", Category: report.CategoryMissingLifecycle},
		{File: "sandbox/main.tf", Category: report.CategoryTutorialPattern},
	}
	rules := []PathRule{{Pattern: "sandbox/**", Categories: []report.Category{report.CategoryMissingLifecycle}}}

	out := ApplyPathRules(findings, rules)
	if len(out) != 1 || out[0].Category != report.CategoryTutorialPattern {
		t.Fatalf("expected only the non-suppressed category to survive, got %#v", out)
	}
}

func TestApplyPathRules_NoRulesReturnsFindingsUnchanged(t *testing.T) {
	findings := []report.Finding{{File: "main.tf"}}
	out := ApplyPathRules(findings, nil)
	if len(out) != 1 {
		t.Fatalf("expected findings unchanged when no rules configured, got %#v", out)
	}
}

func TestApplyPathRules_SingleStarDoesNotCrossPathSeparator(t *testing.T) {
	findings := []report.Finding{
		{File: "modules/a/main.tf", Category: report.CategoryMissingLifecycle},
		{File: "modules/main.tf", Category: report.CategoryMissingLifecycle},
	}
	rules := []PathRule{{Pattern: "modules/*.tf"}}

	out := ApplyPathRules(findings, rules)
	if len(out) != 1 || out[0].File != "modules/a/main.tf" {
		t.Fatalf("expected a single '*' to not match across a '/', got %#v", out)
	}
}
