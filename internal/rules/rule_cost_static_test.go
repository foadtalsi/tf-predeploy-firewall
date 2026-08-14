package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

func staticCostCheck(t *testing.T, threshold float64, headSrc, baseSrc string) []report.Finding {
	t.Helper()
	head, err := parser.ParseFile("main.tf", []byte(headSrc))
	if err != nil {
		t.Fatal(err)
	}
	baseByAddr := map[string]*parser.Resource{}
	if baseSrc != "" {
		base, err := parser.ParseFile("main.tf", []byte(baseSrc))
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range base {
			baseByAddr[r.Address()] = r
		}
	}
	kb, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}
	return StaticCostRule{ThresholdUSD: threshold}.Check(FileInput{
		Path: "main.tf", HeadResources: head, BaseResources: baseByAddr,
	}, kb)
}

func TestStaticCost_FlagsAnExpensiveNewResource(t *testing.T) {
	findings := staticCostCheck(t, 100,
		`resource "aws_instance" "big" { instance_type = "m5.4xlarge" }`, "")

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	f := findings[0]
	if f.Category != report.CategoryCostImpact || f.Severity != report.SeverityMedium {
		t.Errorf("category/severity: %s/%s", f.Category, f.Severity)
	}
	if !strings.Contains(f.Message, "$560/month") {
		t.Errorf("message should carry the m5.4xlarge estimate: %s", f.Message)
	}
	// An estimate that doesn't call itself one gets treated as a quote.
	if !strings.Contains(f.Message, "not a quote") {
		t.Errorf("message must state its own limits: %s", f.Message)
	}
}

func TestStaticCost_FlagsASizeIncrease(t *testing.T) {
	findings := staticCostCheck(t, 50,
		`resource "aws_instance" "web" { instance_type = "m5.2xlarge" }`,
		`resource "aws_instance" "web" { instance_type = "t3.small" }`)

	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(findings), findings)
	}
	if !strings.Contains(findings[0].Message, "from $15 to $280") {
		t.Errorf("message: %s", findings[0].Message)
	}
}

func TestStaticCost_StaysQuiet(t *testing.T) {
	cases := map[string]struct {
		threshold  float64
		head, base string
	}{
		"cheap new resource under threshold": {100,
			`resource "aws_instance" "small" { instance_type = "t3.micro" }`, ""},
		"a size decrease": {50,
			`resource "aws_instance" "web" { instance_type = "t3.small" }`,
			`resource "aws_instance" "web" { instance_type = "m5.2xlarge" }`},
		"unchanged resource": {50,
			`resource "aws_instance" "web" { instance_type = "m5.2xlarge" }`,
			`resource "aws_instance" "web" { instance_type = "m5.2xlarge" }`},
		"unpriced type": {1,
			`resource "aws_iam_role" "r" { name = "x" }`, ""},
		"zero threshold disables": {0,
			`resource "aws_instance" "big" { instance_type = "p3.2xlarge" }`, ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := staticCostCheck(t, c.threshold, c.head, c.base); len(got) != 0 {
				t.Errorf("expected silence, got: %s", got[0].Message)
			}
		})
	}
}

// A module call has no price; guessing one from the module's name would be
// fiction.
func TestStaticCost_IgnoresModules(t *testing.T) {
	if got := staticCostCheck(t, 1,
		"module \"cluster\" {\n  source        = \"./big\"\n  instance_type = \"m5.4xlarge\"\n}\n", ""); len(got) != 0 {
		t.Errorf("modules must not be priced, got: %s", got[0].Message)
	}
}
