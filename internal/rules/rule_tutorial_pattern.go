package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// TutorialPatternRule (category b) flags attribute values that look copied
// from a tutorial rather than adapted for real use: hardcoded secrets,
// wide-open CIDR ranges, and placeholder/generic naming.
type TutorialPatternRule struct{}

var credentialAttrNames = regexp.MustCompile(`(?i)^(password|secret|secret_key|access_key|api_key|token|private_key|client_secret)$`)

// Values that mean "this is intentionally a variable/reference, not a
// hardcoded secret" never reach here because Attribute.IsLiteral is false
// for non-literal expressions (e.g. var.password, data.foo.bar). We only
// look at literal strings.
var placeholderSecretValues = regexp.MustCompile(`(?i)^(changeme|password123?|secret|todo|fixme|xxx+)$`)

var openCIDR = "0.0.0.0/0"

var genericNamePattern = regexp.MustCompile(`(?i)^(example|test|demo|foo|bar|my[-_]?bucket|my[-_]?app|sample|tmp|temp|placeholder)([-_].*)?$`)

func (TutorialPatternRule) Check(in FileInput, aws *schema.AWS) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		findings = append(findings, checkHardcodedCredentials(in.Path, res)...)
		findings = append(findings, checkOpenCIDR(in.Path, res)...)
		findings = append(findings, checkGenericNaming(in.Path, res)...)
	}

	return findings
}

func checkHardcodedCredentials(path string, res *parser.Resource) []report.Finding {
	var findings []report.Finding
	for name, attr := range res.Attributes {
		if !attr.IsLiteral || attr.RawValue == "" {
			continue
		}
		if !credentialAttrNames.MatchString(name) {
			continue
		}
		findings = append(findings, report.Finding{
			File:     path,
			Line:     attr.Range.Start.Line,
			Category: report.CategoryTutorialPattern,
			Severity: report.SeverityCritical,
			Resource: res.Address(),
			Message: fmt.Sprintf(
				"%q is a hardcoded literal value, not a variable/secret reference — credentials should never be committed in plain text",
				name),
		})
	}
	return findings
}

func checkOpenCIDR(path string, res *parser.Resource) []report.Finding {
	var findings []report.Finding

	// Top-level cidr attributes (aws_security_group_rule, etc.)
	for name, attr := range res.Attributes {
		if !attr.IsLiteral || !strings.Contains(strings.ToLower(name), "cidr") {
			continue
		}
		if strings.Contains(attr.RawValue, openCIDR) {
			findings = append(findings, cidrFinding(path, res.Address(), name, attr.Range.Start.Line))
		}
	}

	// Nested blocks: ingress/egress inside aws_security_group, etc.
	for _, blk := range res.Blocks {
		if blk.Type != "ingress" && blk.Type != "egress" {
			continue
		}
		for name, attr := range blk.Attributes {
			if !attr.IsLiteral || !strings.Contains(strings.ToLower(name), "cidr") {
				continue
			}
			if strings.Contains(attr.RawValue, openCIDR) {
				label := fmt.Sprintf("%s (inside %s block)", name, blk.Type)
				findings = append(findings, cidrFinding(path, res.Address(), label, attr.Range.Start.Line))
			}
		}
	}

	return findings
}

func cidrFinding(path, resource, label string, line int) report.Finding {
	return report.Finding{
		File:     path,
		Line:     line,
		Category: report.CategoryTutorialPattern,
		Severity: report.SeverityHigh,
		Resource: resource,
		Message:  fmt.Sprintf("%q includes %s (open to the entire internet) — common tutorial copy-paste, narrow this range", label, openCIDR),
	}
}

func checkGenericNaming(path string, res *parser.Resource) []report.Finding {
	var findings []report.Finding

	if genericNamePattern.MatchString(res.Name) {
		findings = append(findings, report.Finding{
			File:     path,
			Line:     res.DefRange.Start.Line,
			Category: report.CategoryTutorialPattern,
			Severity: report.SeverityLow,
			Resource: res.Address(),
			Message:  fmt.Sprintf("resource local name %q looks like a tutorial placeholder, not a deliberate identifier", res.Name),
		})
	}

	for _, attrName := range []string{"name", "bucket", "identifier", "name_prefix", "bucket_prefix"} {
		attr, ok := res.Attributes[attrName]
		if !ok || !attr.IsLiteral || attr.RawValue == "" {
			continue
		}
		if genericNamePattern.MatchString(attr.RawValue) {
			findings = append(findings, report.Finding{
				File:     path,
				Line:     attr.Range.Start.Line,
				Category: report.CategoryTutorialPattern,
				Severity: report.SeverityLow,
				Resource: res.Address(),
				Message:  fmt.Sprintf("%s = %q looks like a tutorial placeholder value", attrName, attr.RawValue),
			})
		}
	}

	return findings
}
