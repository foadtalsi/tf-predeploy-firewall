package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

func TestAttachDocURLs(t *testing.T) {
	kb, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}

	findings := []report.Finding{
		{Resource: "aws_db_instance.prod"},
		{Resource: "data.aws_db_instance.replica"},
		{Resource: "module.rds"},            // no type of its own
		{Resource: "-"},                     // a whole-file finding
		{Resource: "aws_not_a_real_type.x"}, // covered by no pack
		{Resource: "aws_db_instance.a", DocURL: "https://already.set"},
	}
	AttachDocURLs(findings, kb)

	if !strings.Contains(findings[0].DocURL, "/docs/resources/db_instance") {
		t.Errorf("resource finding got %q", findings[0].DocURL)
	}
	if !strings.Contains(findings[1].DocURL, "/docs/data-sources/db_instance") {
		t.Errorf("data source finding got %q — a data source is documented in its own section", findings[1].DocURL)
	}
	for _, i := range []int{2, 3, 4} {
		if findings[i].DocURL != "" {
			t.Errorf("%s should have no doc link, got %q", findings[i].Resource, findings[i].DocURL)
		}
	}
	if findings[5].DocURL != "https://already.set" {
		t.Error("a link a rule set itself must not be overwritten")
	}
}

func TestAttachDocURLs_NilKnowledgeBaseIsSafe(t *testing.T) {
	findings := []report.Finding{{Resource: "aws_db_instance.prod"}}
	AttachDocURLs(findings, nil)
	if findings[0].DocURL != "" {
		t.Error("expected no link and no panic")
	}
}

// The links have to survive the actual scan path, not just the helper.
func TestRun_AttachesDocURLs(t *testing.T) {
	kb, _ := schema.Load()
	src := []byte("resource \"aws_db_instance\" \"prod\" {\n  identifier = \"prod\"\n}\n")

	res, err := Run([]diff.ChangedFile{{Path: "main.tf", HeadContent: src}},
		kb, []Rule{MissingLifecycleRule{}}, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) == 0 {
		t.Fatal("expected a missing-lifecycle finding")
	}
	if !strings.Contains(res.Findings[0].DocURL, "registry.terraform.io") {
		t.Errorf("Run must attach doc links, got %q", res.Findings[0].DocURL)
	}
}
