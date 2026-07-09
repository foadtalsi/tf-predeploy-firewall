package rules

import (
	"os"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

func mustLoadSchema(t *testing.T) *schema.AWS {
	t.Helper()
	aws, err := schema.Load()
	if err != nil {
		t.Fatalf("schema.Load: %v", err)
	}
	return aws
}

func mustParseFixture(t *testing.T, name string) []*parser.Resource {
	t.Helper()
	src, err := os.ReadFile("../../testdata/fixtures/" + name)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}
	resources, err := parser.ParseFile(name, src)
	if err != nil {
		t.Fatalf("parsing fixture %s: %v", name, err)
	}
	return resources
}

func hasCategory(findings []report.Finding, cat report.Category) bool {
	for _, f := range findings {
		if f.Category == cat {
			return true
		}
	}
	return false
}

func TestUnknownAttributeRule(t *testing.T) {
	aws := mustLoadSchema(t)
	in := FileInput{Path: "unknown_attribute.tf", HeadResources: mustParseFixture(t, "unknown_attribute.tf")}

	findings := UnknownAttributeRule{}.Check(in, aws)
	if !hasCategory(findings, report.CategoryUnknownAttribute) {
		t.Fatalf("expected an unknown_attribute finding, got %#v", findings)
	}
	if findings[0].Resource != "aws_instance.web" {
		t.Errorf("unexpected resource address: %s", findings[0].Resource)
	}
}

func TestTutorialPatternRule(t *testing.T) {
	aws := mustLoadSchema(t)
	in := FileInput{Path: "tutorial_pattern.tf", HeadResources: mustParseFixture(t, "tutorial_pattern.tf")}

	findings := TutorialPatternRule{}.Check(in, aws)
	if !hasCategory(findings, report.CategoryTutorialPattern) {
		t.Fatalf("expected tutorial_pattern findings, got %#v", findings)
	}

	var sawCredential, sawCIDR, sawGenericName bool
	for _, f := range findings {
		switch {
		case f.Resource == "aws_db_instance.example" && f.Severity == report.SeverityCritical:
			sawCredential = true
		case f.Resource == "aws_security_group_rule.open":
			sawCIDR = true
		case f.Resource == "aws_db_instance.example" && f.Severity == report.SeverityLow:
			sawGenericName = true
		}
	}
	if !sawCredential {
		t.Error("expected a hardcoded-credential finding for password = \"changeme\"")
	}
	if !sawCIDR {
		t.Error("expected an open-CIDR finding for 0.0.0.0/0")
	}
	if !sawGenericName {
		t.Error("expected a generic-name finding for resource named \"example\"")
	}
}

func TestForceNewChangeRule(t *testing.T) {
	aws := mustLoadSchema(t)
	base := mustParseFixture(t, "forcenew_base.tf")
	head := mustParseFixture(t, "forcenew_head.tf")

	baseByAddr := map[string]*parser.Resource{}
	for _, r := range base {
		baseByAddr[r.Address()] = r
	}

	in := FileInput{Path: "forcenew_head.tf", HeadResources: head, BaseResources: baseByAddr}
	findings := ForceNewChangeRule{}.Check(in, aws)

	if !hasCategory(findings, report.CategoryForceNewChange) {
		t.Fatalf("expected a force_new_change finding for engine change, got %#v", findings)
	}
	if findings[0].Severity != report.SeverityCritical {
		t.Errorf("expected critical severity (aws_db_instance is a critical stateful type), got %s", findings[0].Severity)
	}
}

func TestForceNewChangeRule_NewResourceSkipped(t *testing.T) {
	aws := mustLoadSchema(t)
	head := mustParseFixture(t, "forcenew_head.tf")

	in := FileInput{Path: "forcenew_head.tf", HeadResources: head, BaseResources: map[string]*parser.Resource{}}
	findings := ForceNewChangeRule{}.Check(in, aws)

	if len(findings) != 0 {
		t.Errorf("expected no findings for a brand-new resource, got %#v", findings)
	}
}

func TestMissingLifecycleRule(t *testing.T) {
	aws := mustLoadSchema(t)
	in := FileInput{Path: "missing_lifecycle.tf", HeadResources: mustParseFixture(t, "missing_lifecycle.tf")}

	findings := MissingLifecycleRule{}.Check(in, aws)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (only the unprotected resource), got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource != "aws_db_instance.unprotected" {
		t.Errorf("expected finding on aws_db_instance.unprotected, got %s", findings[0].Resource)
	}
}

func TestTutorialPatternRule_CredentialValuePatterns(t *testing.T) {
	aws := mustLoadSchema(t)
	in := FileInput{Path: "credential_values.tf", HeadResources: mustParseFixture(t, "credential_values.tf")}

	findings := TutorialPatternRule{}.Check(in, aws)

	var criticals []report.Finding
	for _, f := range findings {
		if f.Severity == report.SeverityCritical {
			criticals = append(criticals, f)
		}
	}
	if len(criticals) == 0 {
		t.Fatal("expected critical findings for AWS key and JWT embedded in literal values, got none")
	}
}

func TestTutorialPatternRule_BoolAttrsNotFlagged(t *testing.T) {
	aws := mustLoadSchema(t)
	src := []byte(`
resource "aws_db_instance" "x" {
  manage_master_user_password = true
  password = "changeme"
}`)
	resources, err := parser.ParseFile("test.tf", src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	in := FileInput{Path: "test.tf", HeadResources: resources}
	findings := TutorialPatternRule{}.Check(in, aws)

	for _, f := range findings {
		if f.Line == 3 {
			t.Errorf("line 3 (bool attr) should not be flagged, got: %s", f.Message)
		}
	}
}

func TestTutorialPatternRule_NestedBlockCIDR(t *testing.T) {
	aws := mustLoadSchema(t)
	in := FileInput{Path: "nested_block_cidr.tf", HeadResources: mustParseFixture(t, "nested_block_cidr.tf")}

	findings := TutorialPatternRule{}.Check(in, aws)

	var cidrFindings []report.Finding
	for _, f := range findings {
		if f.Category == report.CategoryTutorialPattern && f.Severity == report.SeverityHigh {
			cidrFindings = append(cidrFindings, f)
		}
	}
	if len(cidrFindings) == 0 {
		t.Fatal("expected a CIDR finding inside the ingress nested block, got none")
	}
	if cidrFindings[0].Resource != "aws_security_group.wide_open" {
		t.Errorf("unexpected resource: %s", cidrFindings[0].Resource)
	}
}
