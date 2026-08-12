package customrules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/rules"
)

func mustParse(t *testing.T, src string) []*parser.Resource {
	t.Helper()
	resources, err := parser.ParseFile("test.tf", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return resources
}

func TestLoad_ValidatesRequiredFields(t *testing.T) {
	cases := []struct {
		name string
		yaml string
	}{
		{"missing id", `custom_rules: [{resource_type: aws_s3_bucket, severity: high, message: x, pattern: "y"}]`},
		{"missing resource_type", `custom_rules: [{id: r1, severity: high, message: x, pattern: "y"}]`},
		{"bad severity", `custom_rules: [{id: r1, resource_type: "*", severity: extreme, message: x, pattern: "y"}]`},
		{"missing message", `custom_rules: [{id: r1, resource_type: "*", severity: high, pattern: "y"}]`},
		{"bad regex", `custom_rules: [{id: r1, resource_type: "*", severity: high, message: x, pattern: "("}]`},
		{"attribute without pattern", `custom_rules: [{id: r1, resource_type: "*", severity: high, message: x, attribute: acl}]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Load([]byte(c.yaml)); err == nil {
				t.Errorf("expected an error for %s", c.name)
			}
		})
	}
}

func TestLoad_ExistencePatternRule(t *testing.T) {
	cfg, err := Load([]byte(`
custom_rules:
  - id: no-iam-users
    resource_type: aws_iam_user
    severity: medium
    message: "Use aws_iam_role instead of aws_iam_user"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resources := mustParse(t, `
resource "aws_iam_user" "bob" {
  name = "bob"
}
resource "aws_iam_role" "app" {
  name = "app"
}
`)
	in := rules.FileInput{Path: "test.tf", HeadResources: resources}
	findings := cfg.AsEngineRule().Check(in, nil)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource != "aws_iam_user.bob" {
		t.Errorf("expected finding on aws_iam_user.bob, got %s", findings[0].Resource)
	}
	if findings[0].Category != report.Category("custom:no-iam-users") {
		t.Errorf("unexpected category: %s", findings[0].Category)
	}
	if findings[0].Severity != report.SeverityMedium {
		t.Errorf("unexpected severity: %s", findings[0].Severity)
	}
}

func TestLoad_PatternRuleOnAttribute(t *testing.T) {
	cfg, err := Load([]byte(`
custom_rules:
  - id: no-public-acl
    resource_type: aws_s3_bucket
    attribute: acl
    pattern: "public"
    severity: high
    message: "S3 bucket ACL must not be public"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resources := mustParse(t, `
resource "aws_s3_bucket" "logs" {
  acl = "public-read"
}
resource "aws_s3_bucket" "private" {
  acl = "private"
}
`)
	in := rules.FileInput{Path: "test.tf", HeadResources: resources}
	findings := cfg.AsEngineRule().Check(in, nil)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource != "aws_s3_bucket.logs" {
		t.Errorf("expected finding on aws_s3_bucket.logs, got %s", findings[0].Resource)
	}
}

func TestLoad_NegatedRuleFlagsMissingRequiredAttribute(t *testing.T) {
	cfg, err := Load([]byte(`
custom_rules:
  - id: require-env-tag
    resource_type: aws_instance
    attribute: environment_tag
    pattern: ".+"
    negate: true
    severity: low
    message: "aws_instance must set environment_tag"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resources := mustParse(t, `
resource "aws_instance" "web" {
  ami = "ami-123"
}
resource "aws_instance" "tagged" {
  ami             = "ami-123"
  environment_tag = "prod"
}
`)
	in := rules.FileInput{Path: "test.tf", HeadResources: resources}
	findings := cfg.AsEngineRule().Check(in, nil)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding (the untagged resource), got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource != "aws_instance.web" {
		t.Errorf("expected finding on aws_instance.web, got %s", findings[0].Resource)
	}
}

func TestLoad_BlockScopedRule(t *testing.T) {
	cfg, err := Load([]byte(`
custom_rules:
  - id: no-wide-ingress
    resource_type: "*"
    block: ingress
    attribute: cidr_blocks
    pattern: "0\\.0\\.0\\.0/0"
    severity: critical
    message: "ingress block allows 0.0.0.0/0"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resources := mustParse(t, `
resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`)
	in := rules.FileInput{Path: "test.tf", HeadResources: resources}
	findings := cfg.AsEngineRule().Check(in, nil)

	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %#v", len(findings), findings)
	}
}

func TestLoad_NonLiteralAttributeNotGuessed(t *testing.T) {
	cfg, err := Load([]byte(`
custom_rules:
  - id: no-public-acl
    resource_type: aws_s3_bucket
    attribute: acl
    pattern: "public"
    severity: high
    message: "x"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resources := mustParse(t, `
resource "aws_s3_bucket" "dynamic" {
  acl = var.bucket_acl
}
`)
	in := rules.FileInput{Path: "test.tf", HeadResources: resources}
	findings := cfg.AsEngineRule().Check(in, nil)
	if len(findings) != 0 {
		t.Errorf("expected no findings for a non-literal (variable-driven) attribute, got %#v", findings)
	}
}

func TestLoad_WildcardResourceType(t *testing.T) {
	cfg, err := Load([]byte(`
custom_rules:
  - id: banned-name
    resource_type: "*"
    attribute: name
    pattern: "^test"
    severity: low
    message: "no test- prefixed names"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	resources := mustParse(t, `
resource "aws_s3_bucket" "x" {
  name = "test-bucket"
}
resource "aws_iam_role" "y" {
  name = "prod-role"
}
`)
	in := rules.FileInput{Path: "test.tf", HeadResources: resources}
	findings := cfg.AsEngineRule().Check(in, nil)
	if len(findings) != 1 || !strings.Contains(findings[0].Resource, "aws_s3_bucket.x") {
		t.Errorf("expected exactly 1 finding on aws_s3_bucket.x, got %#v", findings)
	}
}
