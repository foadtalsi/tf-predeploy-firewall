package terragrunt

import (
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func TestScanFile_FlagsHardcodedCredentialInInputs(t *testing.T) {
	// "password" (exact) matches credentialAttrNames the same way a .tf
	// resource attribute literally named `password` would — a prefixed
	// name like db_password does NOT match by design (same regex the .tf
	// rule already uses), only the value-pattern check would catch that.
	src := []byte(`
inputs = {
  environment = "prod"
  password    = "SuperSecretPlaintext1"
}
`)
	findings, err := ScanFile("live/prod/terragrunt.hcl", src)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}
	f := findings[0]
	if f.Category != report.CategoryTutorialPattern || f.Severity != report.SeverityCritical {
		t.Errorf("unexpected category/severity: %#v", f)
	}
	if f.Resource != "inputs" {
		t.Errorf("expected Resource to be %q, got %q", "inputs", f.Resource)
	}
}

func TestScanFile_FlagsCredentialValuePatternRegardlessOfKeyName(t *testing.T) {
	src := []byte(`
inputs = {
  some_setting = "AKIAABCDEFGHIJKLMNOP"
}
`)
	findings, err := ScanFile("terragrunt.hcl", src)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for an AWS-key-shaped value, got %d: %#v", len(findings), findings)
	}
}

func TestScanFile_FlagsOpenCIDRInRemoteStateConfig(t *testing.T) {
	src := []byte(`
remote_state {
  backend = "s3"
  config = {
    allowed_cidr = "0.0.0.0/0"
  }
}
`)
	findings, err := ScanFile("terragrunt.hcl", src)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 1 || findings[0].Severity != report.SeverityHigh {
		t.Fatalf("expected 1 high-severity open-CIDR finding, got %#v", findings)
	}
	if findings[0].Resource != "remote_state.config" {
		t.Errorf("expected Resource %q, got %q", "remote_state.config", findings[0].Resource)
	}
}

func TestScanFile_RecursesIntoNestedMaps(t *testing.T) {
	src := []byte(`
inputs = {
  database = {
    host     = "db.internal"
    password = "AnotherSecretValueHere"
  }
}
`)
	findings, err := ScanFile("terragrunt.hcl", src)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected the nested database.password to be found, got %d: %#v", len(findings), findings)
	}
	if findings[0].Resource != "inputs.database" {
		t.Errorf("expected Resource %q, got %q", "inputs.database", findings[0].Resource)
	}
}

func TestScanFile_CleanInputsProduceNoFindings(t *testing.T) {
	src := []byte(`
inputs = {
  environment = "prod"
  instance_count = 3
}
`)
	findings, err := ScanFile("terragrunt.hcl", src)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean inputs, got %#v", findings)
	}
}

func TestScanFile_SkipsVariableReferencesGracefully(t *testing.T) {
	// inputs referencing locals/dependency outputs can't be evaluated with
	// a nil EvalContext — must be skipped, not treated as an error.
	src := []byte(`
locals {
  env = "prod"
}
inputs = {
  environment = local.env
  db_password = dependency.rds.outputs.password
}
`)
	findings, err := ScanFile("terragrunt.hcl", src)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected variable-reference values to be skipped rather than flagged, got %#v", findings)
	}
}

func TestScanFile_InvalidHCLReturnsError(t *testing.T) {
	_, err := ScanFile("terragrunt.hcl", []byte(`inputs = { this is not valid HCL`))
	if err == nil {
		t.Fatal("expected a parse error for malformed HCL")
	}
}
