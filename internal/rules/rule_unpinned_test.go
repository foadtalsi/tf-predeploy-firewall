package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

func unpinnedCheck(t *testing.T, src string) []report.Finding {
	t.Helper()
	res, err := parser.ParseFile("main.tf", []byte(src))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	kb, err := schema.Load()
	if err != nil {
		t.Fatal(err)
	}
	return UnpinnedVersionRule{}.Check(FileInput{
		Path: "main.tf", HeadResources: res, HeadSource: []byte(src),
	}, kb)
}

func firstMessage(findings []report.Finding) string {
	if len(findings) == 0 {
		return ""
	}
	return findings[0].Message
}

func TestUnpinned_FlagsWhatFloats(t *testing.T) {
	cases := map[string]struct {
		src  string
		want string // substring of the expected message
	}{
		"registry module with no version": {
			"module \"vpc\" {\n  source = \"terraform-aws-modules/vpc/aws\"\n}\n",
			"declares no version"},
		"git source with no ref": {
			"module \"m\" {\n  source = \"git::https://github.com/org/mod.git\"\n}\n",
			"no ?ref="},
		"git source pinned to a branch": {
			"module \"m\" {\n  source = \"git::https://github.com/org/mod.git?ref=main\"\n}\n",
			"moving branch"},
		"provider with no version constraint": {
			"terraform {\n  required_providers {\n    aws = {\n      source = \"hashicorp/aws\"\n    }\n  }\n}\n",
			"no version constraint"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := unpinnedCheck(t, c.src)
			if len(got) != 1 {
				t.Fatalf("expected 1 finding, got %d: %v", len(got), got)
			}
			if !strings.Contains(got[0].Message, c.want) {
				t.Errorf("message %q missing %q", got[0].Message, c.want)
			}
			if got[0].Category != report.CategoryUnpinnedVersion {
				t.Errorf("category = %s", got[0].Category)
			}
			if got[0].Suggestion == "" {
				t.Error("a finding whose fix is one argument must carry the suggestion")
			}
		})
	}
}

// False positives here would be constant — every repo has local modules and
// most pin correctly — so silence on the correct forms is the load-bearing
// half of this rule.
func TestUnpinned_StaysQuietOnPinnedAndLocal(t *testing.T) {
	cases := map[string]string{
		"local relative module":   "module \"m\" {\n  source = \"./modules/vpc\"\n}\n",
		"local parent module":     "module \"m\" {\n  source = \"../shared/vpc\"\n}\n",
		"registry module pinned":  "module \"m\" {\n  source  = \"terraform-aws-modules/vpc/aws\"\n  version = \"~> 5.0\"\n}\n",
		"git pinned to a tag":     "module \"m\" {\n  source = \"git::https://github.com/org/mod.git?ref=v1.4.2\"\n}\n",
		"git pinned to a SHA":     "module \"m\" {\n  source = \"git::https://github.com/org/mod.git?ref=9f8a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b\"\n}\n",
		"provider with a version": "terraform {\n  required_providers {\n    aws = {\n      source  = \"hashicorp/aws\"\n      version = \"~> 6.0\"\n    }\n  }\n}\n",
		"a plain resource":        "resource \"aws_vpc\" \"m\" {\n  cidr_block = \"10.0.0.0/16\"\n}\n",
		"no terraform block":      "variable \"x\" {\n  default = 1\n}\n",
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if got := unpinnedCheck(t, src); len(got) != 0 {
				t.Errorf("expected silence, got: %s", firstMessage(got))
			}
		})
	}
}

// Several providers in one block, only the unpinned one reported.
func TestUnpinned_ReportsOnlyTheUnpinnedProvider(t *testing.T) {
	got := unpinnedCheck(t, `
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}
`)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(got), got)
	}
	if got[0].Resource != "provider.random" {
		t.Errorf("resource = %q, want provider.random", got[0].Resource)
	}
	// The line must point at the offending entry, not at the file's top.
	if got[0].Line < 7 {
		t.Errorf("line = %d — should point at the random entry", got[0].Line)
	}
}

// An unrecognised ref is more likely a tag whose shape we don't know than a
// branch; accusing it would be a false positive on someone's release scheme.
func TestUnpinned_SaysNothingAboutAnUnrecognisedRef(t *testing.T) {
	src := "module \"m\" {\n  source = \"git::https://github.com/org/mod.git?ref=release-2024-q1\"\n}\n"
	if got := unpinnedCheck(t, src); len(got) != 0 {
		t.Errorf("expected silence on an unknown ref shape, got: %s", firstMessage(got))
	}
}
