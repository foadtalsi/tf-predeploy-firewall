package tfvars

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func scan(t *testing.T, path, src string) []report.Finding {
	t.Helper()
	got, err := ScanFile(path, []byte(src))
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	return got
}

func messages(findings []report.Finding) string {
	var b strings.Builder
	for _, f := range findings {
		b.WriteString(f.Resource + ": " + f.Message + "\n")
	}
	return b.String()
}

// The case this package exists for. Told to move a secret out of main.tf,
// people move it into terraform.tfvars — and commit that.
func TestScanFile_CatchesACredentialByName(t *testing.T) {
	findings := scan(t, "terraform.tfvars", `
region      = "eu-west-1"
db_password = "hunter2"
instance_ct = 3
`)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d:\n%s", len(findings), messages(findings))
	}
	f := findings[0]
	if f.Severity != report.SeverityCritical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
	if f.Resource != "db_password" {
		t.Errorf("resource = %q", f.Resource)
	}
	if f.Line != 3 {
		t.Errorf("line = %d, want 3", f.Line)
	}
	// A secret in a committed file is already disclosed; deleting the line
	// is not the fix, and the message has to say so.
	if !strings.Contains(f.Message, "rotate") {
		t.Errorf("message must call for rotation: %s", f.Message)
	}
	// …but the same scan runs pre-commit, where nothing is disclosed yet
	// and "already committed" would be a false alarm. The rotation advice
	// must be stated as a condition, not as a fact.
	if strings.Contains(f.Message, "committed in a") {
		t.Errorf("message asserts a commit that may not have happened: %s", f.Message)
	}
	if !strings.Contains(f.Message, "If this file is already committed") {
		t.Errorf("rotation advice must be conditional: %s", f.Message)
	}
}

// A .tfvars value can be an object of settings; a credential nested in one
// is no less committed.
func TestScanFile_RecursesIntoObjectsAndLists(t *testing.T) {
	findings := scan(t, "prod.auto.tfvars", `
database = {
  host     = "db.internal"
  password = "hunter2"
}
allowed_cidrs = ["10.0.0.0/8", "0.0.0.0/0"]
`)
	got := messages(findings)
	if !strings.Contains(got, "database.password") {
		t.Errorf("nested credential missed:\n%s", got)
	}
	// The path locates it, the leaf name identifies it as a credential.
	if !strings.Contains(got, "0.0.0.0/0") {
		t.Errorf("open CIDR inside a list missed:\n%s", got)
	}
}

func TestScanFile_CatchesCredentialShapesAndEntropy(t *testing.T) {
	findings := scan(t, "terraform.tfvars", `
some_opaque_setting = "AKIAIOSFODNN7EXAMPLE"
another_setting     = "Vt5wYq2Jn8RkLp3zXcB7dHm4gFa9eSu6TbNr"
`)
	got := messages(findings)
	if !strings.Contains(got, "AWS access key") {
		t.Errorf("known credential format missed:\n%s", got)
	}
	if !strings.Contains(got, "high-entropy") {
		t.Errorf("entropy fallback missed:\n%s", got)
	}
}

// False positives are what get a scanner switched off. A .tfvars file is
// mostly ordinary configuration and must stay silent.
func TestScanFile_StaysQuietOnOrdinaryValues(t *testing.T) {
	findings := scan(t, "terraform.tfvars", `
region          = "eu-west-1"
instance_type   = "t3.medium"
instance_count  = 3
enable_backups  = true
vpc_cidr        = "10.0.0.0/16"
bucket_arn      = "arn:aws:s3:::prod-logs-eu-west-1-longish-name"
tags            = { owner = "platform", env = "production" }
public_key      = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDZ1x2y3z4"
subnet_ids      = ["subnet-0a1b2c3d4e5f6a7b8", "subnet-1b2c3d4e5f6a7b8c9"]
`)
	if len(findings) != 0 {
		t.Errorf("expected silence on ordinary configuration, got:\n%s", messages(findings))
	}
}

// A value the scanner cannot resolve must never be guessed at.
func TestScanFile_SkipsUnresolvableValues(t *testing.T) {
	findings := scan(t, "terraform.tfvars", `password = file("secret.txt")`)
	if len(findings) != 0 {
		t.Errorf("a function call has no literal value to judge, got:\n%s", messages(findings))
	}
}

func TestScanFile_HandlesTheJSONForm(t *testing.T) {
	findings := scan(t, "terraform.tfvars.json", `{
  "region": "eu-west-1",
  "db_password": "hunter2",
  "database": {"admin_password": "s3cret"}
}`)
	got := messages(findings)
	if !strings.Contains(got, "db_password") || !strings.Contains(got, "database.admin_password") {
		t.Errorf("json credentials missed:\n%s", got)
	}
}

// A file the scanner cannot read is a gap the caller should report, not one
// it should silently skip.
func TestScanFile_ReportsParseErrors(t *testing.T) {
	if _, err := ScanFile("bad.tfvars", []byte(`this is = not ( valid`)); err == nil {
		t.Error("expected a parse error")
	}
	if _, err := ScanFile("bad.tfvars.json", []byte(`{not json`)); err == nil {
		t.Error("expected a json parse error")
	}
}

func TestIsTfvarsPath(t *testing.T) {
	for _, p := range []string{"terraform.tfvars", "prod.auto.tfvars", "a/b/x.tfvars", "terraform.tfvars.json"} {
		if !IsTfvarsPath(p) {
			t.Errorf("%q should be recognised", p)
		}
	}
	for _, p := range []string{"main.tf", "terragrunt.hcl", "vars.tf", "notes.txt"} {
		if IsTfvarsPath(p) {
			t.Errorf("%q should not be recognised", p)
		}
	}
}
