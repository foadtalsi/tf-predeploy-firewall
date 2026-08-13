package parser

import (
	"testing"
)

const sampleTF = `
resource "aws_db_instance" "primary" {
  identifier = "prod-db"
  engine     = "postgres"
  username   = "admin"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_security_group" "web" {
  name   = "web-sg"
  vpc_id = "vpc-123"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
`

func TestParseFile_TopLevelAttributes(t *testing.T) {
	resources, err := ParseFile("test.tf", []byte(sampleTF))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(resources) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(resources))
	}

	db := resources[0]
	if db.Address() != "aws_db_instance.primary" {
		t.Errorf("unexpected address: %s", db.Address())
	}
	if _, ok := db.Attributes["identifier"]; !ok {
		t.Error("expected attribute 'identifier' to be captured")
	}
	attr := db.Attributes["identifier"]
	if !attr.IsLiteral || attr.RawValue != "prod-db" {
		t.Errorf("unexpected identifier value: %q (literal=%v)", attr.RawValue, attr.IsLiteral)
	}
}

func TestParseFile_LifecycleBlock(t *testing.T) {
	resources, err := ParseFile("test.tf", []byte(sampleTF))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	db := resources[0]
	if !db.HasLifecycleBlock {
		t.Error("expected HasLifecycleBlock = true")
	}
	if db.PreventDestroyValue == nil {
		t.Fatal("expected PreventDestroyValue to be set")
	}
	if !*db.PreventDestroyValue {
		t.Error("expected prevent_destroy = true")
	}
}

func TestParseFile_NestedBlocks(t *testing.T) {
	resources, err := ParseFile("test.tf", []byte(sampleTF))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	sg := resources[1]
	if sg.Address() != "aws_security_group.web" {
		t.Fatalf("unexpected address: %s", sg.Address())
	}
	if len(sg.Blocks) != 1 {
		t.Fatalf("expected 1 nested block (ingress), got %d", len(sg.Blocks))
	}
	blk := sg.Blocks[0]
	if blk.Type != "ingress" {
		t.Errorf("expected block type 'ingress', got %q", blk.Type)
	}
	cidrAttr, ok := blk.Attributes["cidr_blocks"]
	if !ok {
		t.Fatal("expected cidr_blocks attribute inside ingress block")
	}
	if !cidrAttr.IsLiteral {
		t.Error("expected cidr_blocks to be a literal")
	}
	if cidrAttr.RawValue != "0.0.0.0/0" {
		t.Errorf("unexpected cidr_blocks value: %q", cidrAttr.RawValue)
	}
}

func TestParseFile_MalformedHCL(t *testing.T) {
	_, err := ParseFile("bad.tf", []byte(`resource "aws_instance" "x" {`))
	if err == nil {
		t.Error("expected an error for malformed HCL, got nil")
	}
}

// Module calls and data sources are parsed alongside resources: a mature
// Terraform repo is mostly module calls, and a password passed to a module is
// exactly as hardcoded as one passed to a resource. Declaration blocks
// (variable, locals, output) are not — they declare, they don't configure
// infrastructure.
func TestParseFile_ParsesResourcesModulesAndDataSources(t *testing.T) {
	src := `
variable "region" { default = "us-east-1" }
locals { env = "prod" }
output "vpc_id" { value = "x" }

data "aws_ami" "ubuntu" { most_recent = true }
module "rds" {
  source          = "./modules/rds"
  master_password = "hunter2"
}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
`
	resources, err := ParseFile("test.tf", []byte(src))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	byAddr := map[string]*Resource{}
	for _, r := range resources {
		byAddr[r.Address()] = r
	}

	if len(byAddr) != 3 {
		t.Fatalf("expected 3 blocks (resource, module, data), got %d: %v", len(byAddr), keys(byAddr))
	}

	for addr, wantKind := range map[string]Kind{
		"aws_vpc.main":        KindResource,
		"module.rds":          KindModule,
		"data.aws_ami.ubuntu": KindData,
	} {
		got, ok := byAddr[addr]
		if !ok {
			t.Errorf("missing %s; got %v", addr, keys(byAddr))
			continue
		}
		if got.Kind != wantKind {
			t.Errorf("%s: Kind = %q, want %q", addr, got.Kind, wantKind)
		}
	}

	// The module's arguments must be readable, since that is the whole point.
	if pw := byAddr["module.rds"].Attributes["master_password"]; pw == nil || pw.RawValue != "hunter2" {
		t.Errorf("module argument not captured: %#v", byAddr["module.rds"].Attributes["master_password"])
	}
}

func keys(m map[string]*Resource) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Resolution through a variable default or a local: the value a rule sees must
// be the value the attribute actually carries, not the reference text.
func TestParseFileWithContext_ResolvesVarsAndLocals(t *testing.T) {
	src := `
variable "db_password" { default = "changeme" }
locals { admin_user = "root" }

resource "aws_db_instance" "prod" {
  password = var.db_password
  username = local.admin_user
  engine   = "postgres"
}
`
	scope := BuildScope(map[string][]byte{"main.tf": []byte(src)})
	if scope == nil {
		t.Fatal("expected a scope from a file declaring a variable default and a local")
	}

	resources, err := ParseFileWithContext("main.tf", []byte(src), scope)
	if err != nil {
		t.Fatalf("ParseFileWithContext: %v", err)
	}
	attrs := resources[0].Attributes

	if got := attrs["password"]; !got.IsLiteral || got.RawValue != "changeme" {
		t.Errorf("password should resolve through the variable default, got %#v", got)
	}
	if got := attrs["password"].ResolvedFrom; got != "var.db_password" {
		t.Errorf("ResolvedFrom = %q, want var.db_password — a finding on this line has to say where the value lives", got)
	}
	if got := attrs["username"]; !got.IsLiteral || got.RawValue != "root" || got.ResolvedFrom != "local.admin_user" {
		t.Errorf("username should resolve through the local, got %#v", got)
	}
	// An inline literal is not "resolved from" anything.
	if got := attrs["engine"]; !got.IsLiteral || got.ResolvedFrom != "" {
		t.Errorf("inline literal should carry no ResolvedFrom, got %#v", got)
	}
}

// The scope must never invent a value. A variable with no default is supplied
// at plan time, and guessing would be how false positives get in.
func TestParseFileWithContext_LeavesUnresolvableValuesAlone(t *testing.T) {
	src := `
variable "db_password" {}

resource "aws_db_instance" "prod" {
  password       = var.db_password
  something_else = aws_kms_key.k.arn
}
`
	scope := BuildScope(map[string][]byte{"main.tf": []byte(src)})
	resources, err := ParseFileWithContext("main.tf", []byte(src), scope)
	if err != nil {
		t.Fatalf("ParseFileWithContext: %v", err)
	}
	for _, name := range []string{"password", "something_else"} {
		if got := resources[0].Attributes[name]; got.IsLiteral {
			t.Errorf("%s must stay unresolved, got %#v", name, got)
		}
	}
}

// Terraform scopes locals per directory, so a local declared in one file has
// to be visible when scanning another.
func TestBuildScope_IsDirectoryWide(t *testing.T) {
	scope := BuildScope(map[string][]byte{
		"locals.tf": []byte(`locals { admin_pw = "s3cret" }`),
		"rds.tf":    []byte(`resource "aws_db_instance" "p" { password = local.admin_pw }`),
	})
	resources, err := ParseFileWithContext("rds.tf",
		[]byte(`resource "aws_db_instance" "p" { password = local.admin_pw }`), scope)
	if err != nil {
		t.Fatalf("ParseFileWithContext: %v", err)
	}
	if got := resources[0].Attributes["password"]; !got.IsLiteral || got.RawValue != "s3cret" {
		t.Errorf("a local from a sibling file should resolve, got %#v", got)
	}
}
