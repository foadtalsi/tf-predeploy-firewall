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

func TestParseFile_NonResourceBlocksIgnored(t *testing.T) {
	src := `
variable "region" { default = "us-east-1" }
data "aws_ami" "ubuntu" {}
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
`
	resources, err := ParseFile("test.tf", []byte(src))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	if len(resources) != 1 || resources[0].Type != "aws_vpc" {
		t.Errorf("expected exactly the aws_vpc resource, got %d resources", len(resources))
	}
}
