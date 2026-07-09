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

var credentialAttrNames = regexp.MustCompile(`(?i)^(password|secret|secret_key|access_key|api_key|token|private_key|client_secret|auth_token|master_password)$`)

var openCIDR = "0.0.0.0/0"

var genericNamePattern = regexp.MustCompile(`(?i)^(example|test|demo|foo|bar|my[-_]?bucket|my[-_]?app|sample|tmp|temp|placeholder)([-_].*)?$`)

// credentialValuePatterns detects high-entropy or well-known credential
// formats embedded in any string literal, regardless of the attribute name.
// These are ordered cheapest-to-most-specific; first match wins for message.
var credentialValuePatterns = []struct {
	re      *regexp.Regexp
	label   string
}{
	// AWS access key ID
	{regexp.MustCompile(`AKIA[A-Z0-9]{16}`), "AWS access key ID (AKIA…)"},
	// AWS secret access key: 40-char base64url
	{regexp.MustCompile(`(?i)[a-z0-9/+]{40}`), "possible AWS secret key (40-char base64)"},
	// PEM private key header
	{regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), "PEM private key"},
	// JWT (3 base64url segments separated by dots)
	{regexp.MustCompile(`^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`), "JWT token"},
	// GitHub PAT (classic ghp_ or fine-grained github_pat_)
	{regexp.MustCompile(`^(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})$`), "GitHub personal access token"},
	// Generic high-entropy hex string (32+ chars: MD5/SHA/UUID-ish secrets)
	{regexp.MustCompile(`^[0-9a-f]{32,}$`), "high-entropy hex string (possible secret)"},
}

func (TutorialPatternRule) Check(in FileInput, aws *schema.AWS) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		findings = append(findings, checkHardcodedCredentials(in.Path, res)...)
		findings = append(findings, checkCredentialValues(in.Path, res)...)
		findings = append(findings, checkOpenCIDR(in.Path, res)...)
		findings = append(findings, checkGenericNaming(in.Path, res)...)
	}

	return findings
}

func checkHardcodedCredentials(path string, res *parser.Resource) []report.Finding {
	var findings []report.Finding
	for name, attr := range res.Attributes {
		// Only flag string literals: bools (manage_master_user_password = true)
		// and numbers are never credentials.
		if !attr.IsLiteral || attr.RawValue == "" || attr.RawValue == "true" || attr.RawValue == "false" {
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
				"%q is a hardcoded string literal, not a variable or secret reference — credentials must not be committed in plain text",
				name),
		})
	}
	return findings
}

// checkCredentialValues scans ALL literal string attributes for known
// credential patterns regardless of the attribute name. This catches cases
// like `user_data = "AKIAIOSFODNN7EXAMPLE..."` or a PEM key embedded in
// an arbitrary field.
func checkCredentialValues(path string, res *parser.Resource) []report.Finding {
	var findings []report.Finding
	checkAttrs := func(attrs map[string]*parser.Attribute, locationPrefix string) {
		for name, attr := range attrs {
			if !attr.IsLiteral || len(attr.RawValue) < 16 {
				continue
			}
			// Skip attrs already caught by checkHardcodedCredentials to avoid
			// duplicate findings on the same line.
			if credentialAttrNames.MatchString(name) {
				continue
			}
			for _, pat := range credentialValuePatterns {
				if pat.re.MatchString(attr.RawValue) {
					findings = append(findings, report.Finding{
						File:     path,
						Line:     attr.Range.Start.Line,
						Category: report.CategoryTutorialPattern,
						Severity: report.SeverityCritical,
						Resource: res.Address(),
						Message: fmt.Sprintf(
							"%s%q value matches pattern: %s — remove from source and use a secret reference",
							locationPrefix, name, pat.label),
					})
					break // one match per attribute is enough
				}
			}
		}
	}
	checkAttrs(res.Attributes, "")
	for _, blk := range res.Blocks {
		checkAttrs(blk.Attributes, fmt.Sprintf("(inside %s block) ", blk.Type))
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
