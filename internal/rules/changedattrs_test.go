package rules

import (
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
)

func TestChangedAttrsForResource(t *testing.T) {
	base := mustParseFixture(t, "forcenew_base.tf")[0] // aws_db_instance.primary: identifier, engine, username
	head := mustParseFixture(t, "forcenew_head.tf")[0] // same, engine changed postgres->mysql

	changed := changedAttrsForResource(head, base)

	if !changed["engine"] {
		t.Errorf("expected 'engine' to be flagged as changed, got %v", changed)
	}
	if changed["identifier"] {
		t.Errorf("did not expect 'identifier' to be flagged as changed, got %v", changed)
	}
	if changed["username"] {
		t.Errorf("did not expect 'username' to be flagged as changed, got %v", changed)
	}
}

func TestChangedAttrsForResource_NestedBlock(t *testing.T) {
	baseSrc := `resource "aws_instance" "web" {
  ami = "ami-123"
  root_block_device {
    volume_type = "gp2"
  }
}`
	headSrc := `resource "aws_instance" "web" {
  ami = "ami-123"
  root_block_device {
    volume_type = "gp3"
  }
}`
	base, err := parser.ParseFile("base.tf", []byte(baseSrc))
	if err != nil {
		t.Fatalf("parse base: %v", err)
	}
	head, err := parser.ParseFile("head.tf", []byte(headSrc))
	if err != nil {
		t.Fatalf("parse head: %v", err)
	}

	changed := changedAttrsForResource(head[0], base[0])

	if !changed["root_block_device.volume_type"] {
		t.Errorf("expected 'root_block_device.volume_type' to be flagged as changed, got %v", changed)
	}
	if changed["ami"] {
		t.Errorf("did not expect 'ami' to be flagged as changed, got %v", changed)
	}
}
