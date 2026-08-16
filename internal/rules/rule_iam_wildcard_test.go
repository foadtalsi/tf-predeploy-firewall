package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
)

// iamFindings runs the rule over a snippet of Terraform and returns its
// findings. The source is parsed for real rather than hand-built, because
// this rule's entire input is the raw byte range the parser records — a
// FileInput assembled by hand would exercise nothing.
func iamFindings(t *testing.T, src string) []string {
	t.Helper()
	resources, err := parser.ParseFile("test.tf", []byte(src))
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	in := FileInput{Path: "test.tf", HeadResources: resources, HeadSource: []byte(src)}

	var out []string
	for _, f := range (IAMWildcardRule{}).Check(in, nil) {
		out = append(out, f.Message)
	}
	return out
}

func TestIAMWildcard_FindsActionStarInJSONEncode(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_role_policy" "admin" {
  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}`)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(got), got)
	}
	// Action + Resource together is administrator, and the message has to say
	// so rather than reporting the weaker "grants every action".
	if !strings.Contains(got[0], "unrestricted administrator access") {
		t.Errorf("Action \"*\" on Resource \"*\" was not reported as administrator: %s", got[0])
	}
}

func TestIAMWildcard_ActionStarAloneIsStillReported(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_role_policy" "wide" {
  policy = jsonencode({
    Statement = [{
      Action   = "*"
      Resource = "arn:aws:s3:::acme/*"
    }]
  })
}`)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(got), got)
	}
	if strings.Contains(got[0], "administrator") {
		t.Errorf("a scoped resource was described as account-wide administrator: %s", got[0])
	}
}

// The whole reason this rule is compiled instead of declarative: heredoc and
// jsonencode must both be read, or the scanner catches the spelling nobody
// uses and misses the one everybody does.
func TestIAMWildcard_ReadsHeredocPolicies(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_policy" "admin" {
  policy = <<-POLICY
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": "*",
        "Resource": "*"
      }]
    }
  POLICY
}`)
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(got), got)
	}
}

func TestIAMWildcard_ReadsListForm(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_role_policy" "admin" {
  policy = jsonencode({
    Statement = [{ Action = ["*"], Resource = ["*"] }]
  })
}`)
	if len(got) != 1 {
		t.Fatalf("Action = [\"*\"] was not detected: %v", got)
	}
}

// The single largest false-positive source if it were reported alone: a
// wildcard resource is unavoidable for the many actions whose API takes no
// ARN.
func TestIAMWildcard_ResourceStarAloneIsNotAFinding(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_role_policy" "describe" {
  policy = jsonencode({
    Statement = [{
      Action   = ["ec2:DescribeInstances", "s3:ListAllMyBuckets"]
      Resource = "*"
    }]
  })
}`)
	if len(got) != 0 {
		t.Errorf("Resource \"*\" alone was reported: %v", got)
	}
}

// "s3:*" is a service wildcard. Narrowing it is least-privilege work in
// progress, not a finding — and treating it as one would fire on a large
// share of real policies.
func TestIAMWildcard_ServiceWildcardIsNotActionStar(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_role_policy" "s3admin" {
  policy = jsonencode({
    Statement = [{
      Action   = ["s3:*", "iam:PassRole"]
      Resource = "*"
    }]
  })
}`)
	if len(got) != 0 {
		t.Errorf("a scoped service wildcard was reported as Action \"*\": %v", got)
	}
}

func TestIAMWildcard_FindsPublicPrincipal(t *testing.T) {
	for name, src := range map[string]string{
		"bare star": `
resource "aws_s3_bucket_policy" "public" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Principal = "*", Action = "s3:GetObject" }]
  })
}`,
		"aws wrapper": `
resource "aws_iam_role" "anyone" {
  assume_role_policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { AWS = "*" } }]
  })
}`,
	} {
		t.Run(name, func(t *testing.T) {
			got := iamFindings(t, src)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1: %v", len(got), got)
			}
			if !strings.Contains(got[0], "Principal") {
				t.Errorf("wrong finding: %s", got[0])
			}
		})
	}
}

// Public principal narrowed by a Condition is the org-wide pattern and is
// correct. The suppression is document-wide rather than per-statement, which
// trades a false negative for a false positive on purpose.
func TestIAMWildcard_ConditionSuppressesThePrincipalFinding(t *testing.T) {
	got := iamFindings(t, `
resource "aws_s3_bucket_policy" "org" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Condition = { StringEquals = { "aws:PrincipalOrgID" = "o-acme" } }
    }]
  })
}`)
	if len(got) != 0 {
		t.Errorf("a condition-narrowed public principal was reported: %v", got)
	}
}

// A Condition must not silence the action check too — those are independent
// problems, and an org-scoped grant of every action is still every action.
func TestIAMWildcard_ConditionDoesNotSuppressTheActionFinding(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_role_policy" "org_admin" {
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Action    = "*"
      Resource  = "*"
      Condition = { StringEquals = { "aws:PrincipalOrgID" = "o-acme" } }
    }]
  })
}`)
	if len(got) != 1 {
		t.Errorf("a Condition silenced the wildcard-action finding: %v", got)
	}
}

// policy_arn, ssl_policy and friends hold a name or an ARN, not a document.
// Reading one as a policy would produce a finding about text that is not a
// policy at all.
func TestIAMWildcard_IgnoresAttributesThatMerelyContainPolicy(t *testing.T) {
	got := iamFindings(t, `
resource "aws_iam_role_policy_attachment" "app" {
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lb_listener" "web" {
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}`)
	if len(got) != 0 {
		t.Errorf("an attribute holding an ARN was read as a policy document: %v", got)
	}
}

// A wildcard forty lines into a jsonencode block must be reported where it is
// written. Pointing at the `policy =` line instead would send the reader to
// the top of a block and leave them to find it.
func TestIAMWildcard_ReportsTheLineTheWildcardIsOn(t *testing.T) {
	src := `resource "aws_iam_role_policy" "admin" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "one"
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::acme/*"
      },
      {
        Sid      = "two"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
    ]
  })
}`
	resources, err := parser.ParseFile("test.tf", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	in := FileInput{Path: "test.tf", HeadResources: resources, HeadSource: []byte(src)}

	findings := (IAMWildcardRule{}).Check(in, nil)
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Line != 14 {
		t.Errorf("reported line %d, want 14 (the Action = \"*\" line, not the policy = line)", findings[0].Line)
	}
}

// Unit tests elsewhere build a FileInput with no source. This rule has
// nothing to read in that case and must return nothing rather than panic.
func TestIAMWildcard_NoSourceIsNotAPanic(t *testing.T) {
	in := FileInput{Path: "test.tf", HeadResources: nil}
	if got := (IAMWildcardRule{}).Check(in, nil); len(got) != 0 {
		t.Errorf("got findings with no source: %v", got)
	}
}
