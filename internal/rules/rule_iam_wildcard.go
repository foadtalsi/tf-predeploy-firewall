package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// IAMWildcardRule flags IAM policy documents that grant every action, or
// grant to every principal.
//
// # Why this is compiled rather than declarative
//
// The matcher can only see attribute values that statically evaluate to a
// literal, and a modern IAM policy almost never does. The form the AWS
// provider documentation uses, and the one generated Terraform reproduces, is
//
//	policy = jsonencode({ Statement = [{ Action = "*", Resource = "*" }] })
//
// which is a function call over an object expression. The parser resolves it
// to nothing, so `value_matches` has nothing to match against. Heredoc
// policies do arrive as literals and could be matched — but writing the rule
// for only the form that happens to be visible would mean the scanner catches
// the older, rarer spelling and misses the one people actually write.
//
// So this rule works on the attribute's raw source range instead, which the
// parser records even when it cannot evaluate the expression. Same technique
// as UnpinnedVersionRule, for the same reason: the information exists in the
// file and nowhere in the resource model.
//
// # What it deliberately does not flag
//
// `Resource: "*"` on its own. It is unavoidable for a large family of actions
// whose API takes no resource ARN — s3:ListAllMyBuckets, ec2:DescribeInstances,
// most of iam:List* — so a rule that flagged it would fire on a large share of
// correct policies. A wildcard resource is only reported here when paired with
// a wildcard action, where the pair means "administrator".
//
// A `Principal: "*"` inside a document that also carries a Condition. The
// org-wide pattern — public principal narrowed by aws:PrincipalOrgID or
// aws:SourceArn — is both common and correct, and telling those two apart
// needs statement-level scoping this rule does not attempt. Suppressing the
// whole document when any Condition appears trades a false negative for a
// false positive, which is the right direction: an unfounded accusation is
// what gets a scanner switched off.
type IAMWildcardRule struct{}

// policyAttrNames are the attributes whose value is an IAM policy document.
//
// Matched by exact name rather than by suffix. "policy" as a substring
// appears on plenty of attributes that hold a policy *name* or ARN —
// policy_arn, iam_policy_name, ssl_policy — and reading one of those as a
// document would produce a finding about text that is not a policy at all.
var policyAttrNames = map[string]bool{
	"policy":             true,
	"assume_role_policy": true,
	"policy_document":    true,
	"access_policy":      true,
	"repository_policy":  true,
	"bucket_policy":      true,
}

var (
	// Action = "*" / "Action": "*" / Action = ["*"], in HCL object syntax or
	// JSON. NotAction is deliberately absent: it is rare, and its wildcard
	// semantics are inverted.
	wildcardActionRe = regexp.MustCompile(`(?i)"?\bAction"?\s*[:=]\s*(?:\[\s*)?"\*"`)

	// Resource = "*", used only to decide whether a wildcard action is an
	// account-wide grant or merely a broad one.
	wildcardResourceRe = regexp.MustCompile(`(?i)"?\bResource"?\s*[:=]\s*(?:\[\s*)?"\*"`)

	// Principal = "*" and Principal = { AWS = "*" }, the two spellings of
	// "anyone". The optional middle group absorbs the AWS/Service wrapper
	// without allowing a nested brace, so it cannot run past the end of the
	// principal block and match an unrelated star further down.
	wildcardPrincipalRe = regexp.MustCompile(`(?i)"?\bPrincipal"?\s*[:=]\s*(?:\{[^{}]*?"?AWS"?\s*[:=]\s*)?(?:\[\s*)?"\*"`)

	// Any Condition key at all. Its presence suppresses the principal check.
	conditionRe = regexp.MustCompile(`(?i)"?\bCondition"?\s*[:=]`)
)

func (IAMWildcardRule) Check(in FileInput, kb *schema.KnowledgeBase) []report.Finding {
	if len(in.HeadSource) == 0 {
		// Without the raw source there is nothing to read: this rule's whole
		// input is the text the parser could not evaluate. Unit tests that
		// build a FileInput by hand simply get no findings, which is the same
		// contract the fix-emitting rules already have.
		return nil
	}

	var findings []report.Finding
	for _, res := range in.HeadResources {
		// sortedKeys, not a bare map range: findings are compared against a
		// golden file, and map order would make that file rewrite itself.
		for _, name := range sortedKeys(res.Attributes) {
			if !policyAttrNames[name] {
				continue
			}
			attr := res.Attributes[name]
			body := sourceInRange(in.HeadSource, attr.Range)
			if body == "" {
				continue
			}
			findings = append(findings, checkPolicyBody(in.Path, res, attr, body)...)
		}
	}
	return findings
}

func checkPolicyBody(path string, res *parser.Resource, attr *parser.Attribute, body string) []report.Finding {
	var findings []report.Finding

	if loc := wildcardActionRe.FindStringIndex(body); loc != nil {
		detail := fmt.Sprintf(
			"the IAM policy on %s grants Action \"*\" — every action in every AWS service, including the IAM calls that would let a holder grant itself anything else",
			res.Address())
		if wildcardResourceRe.MatchString(body) {
			detail = fmt.Sprintf(
				"the IAM policy on %s grants Action \"*\" on Resource \"*\" — this is unrestricted administrator access to the account, which is almost never what a service needs",
				res.Address())
		}
		findings = append(findings, report.Finding{
			File:     path,
			Line:     lineOfOffset(body, loc[0], attr.Range.Start.Line),
			Category: report.CategoryPermissiveIAM,
			Severity: report.SeverityHigh,
			Resource: res.Address(),
			Message:  detail,
			Suggestion: `# Name the actions this actually needs, and the resources it needs them on:
Action   = ["s3:GetObject", "s3:PutObject"]
Resource = ["${aws_s3_bucket.data.arn}/*"]`,
		})
	}

	// A public principal narrowed by a Condition is the org-wide pattern and
	// is correct; see the type comment for why this suppression is
	// document-wide rather than per-statement.
	if !conditionRe.MatchString(body) {
		if loc := wildcardPrincipalRe.FindStringIndex(body); loc != nil {
			findings = append(findings, report.Finding{
				File:     path,
				Line:     lineOfOffset(body, loc[0], attr.Range.Start.Line),
				Category: report.CategoryPermissiveIAM,
				Severity: report.SeverityHigh,
				Resource: res.Address(),
				Message: fmt.Sprintf(
					"the policy on %s names Principal \"*\" with no Condition — this grants the listed actions to every AWS account on earth, not to every principal in yours",
					res.Address()),
				Suggestion: `# Name the accounts or roles, or keep "*" and narrow it:
Condition = {
  StringEquals = { "aws:PrincipalOrgID" = "o-example" }
}`,
			})
		}
	}

	return findings
}

// sourceInRange returns the text an attribute occupies, using the byte
// offsets HCL recorded. Ranges come from the same file that produced them, so
// an out-of-bounds offset means the caller paired a resource with the wrong
// source; returning empty makes that a missed finding rather than a panic
// inside somebody else's CI.
func sourceInRange(src []byte, r hcl.Range) string {
	start, end := r.Start.Byte, r.End.Byte
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	return string(src[start:end])
}

// lineOfOffset converts a byte offset within an attribute's text back to a
// file line, so a wildcard buried in a forty-line jsonencode block is reported
// where it is written rather than at the top of the attribute.
func lineOfOffset(body string, offset, startLine int) int {
	if offset < 0 || offset > len(body) {
		return startLine
	}
	return startLine + strings.Count(body[:offset], "\n")
}
