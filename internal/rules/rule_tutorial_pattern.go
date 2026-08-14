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

// credentialAttrNames matches attribute names that carry a credential.
//
// Suffix-based (`.*_password`, not just `password`) because every provider
// grows its own vocabulary — azurerm alone has administrator_login_password,
// admin_password and account_password, and an exact-match list rebuilt per
// provider would always be one release behind. "key" is deliberately NOT a
// bare suffix: public_key, partition_key and kms_key_id are not secrets, so
// only the specific key-ish names appear. Values that look like credentials
// regardless of their attribute name are checkCredentialValues's job.
var credentialAttrNames = regexp.MustCompile(`(?i)^(?:.*_)?(password|passwd|secret|secret_key|access_key|api_key|token|private_key|client_secret|auth_token|connection_string)$`)

var openCIDR = "0.0.0.0/0"

var genericNamePattern = regexp.MustCompile(`(?i)^(example|test|demo|foo|bar|my[-_]?bucket|my[-_]?app|sample|tmp|temp|placeholder)([-_].*)?$`)

// credentialValuePatterns detects high-entropy or well-known credential
// formats embedded in any string literal, regardless of the attribute name.
// These are ordered cheapest-to-most-specific; first match wins for message.
//
// A pattern may carry a confirm function, applied to the matched text. It
// exists for shapes loose enough to hit ordinary strings: the character
// class alone cannot tell a secret from a long path, but randomness can.
var credentialValuePatterns = []struct {
	re      *regexp.Regexp
	label   string
	confirm func(match string) bool
}{
	// AWS access key ID
	{re: regexp.MustCompile(`AKIA[A-Z0-9]{16}`), label: "AWS access key ID (AKIA…)"},
	// AWS secret access key: 40 characters of base64.
	//
	// The character class matches any 40-char run of [a-z0-9/+], which a
	// file path reaches easily — "infra/terraform/build/dashboard/bootstrap"
	// is 41 — and reporting a build command as a leaked AWS key at critical
	// severity is precisely the false positive that gets a scanner switched
	// off. A real secret is base64 output: mixed case, digits, and high
	// entropy. Requiring that keeps the detection and drops the paths.
	{
		re:      regexp.MustCompile(`(?i)[a-z0-9/+]{40}`),
		label:   "possible AWS secret key (40-char base64)",
		confirm: looksLikeBase64Secret,
	},
	// PEM private key header
	{re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`), label: "PEM private key"},
	// JWT (3 base64url segments separated by dots)
	{re: regexp.MustCompile(`^ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`), label: "JWT token"},
	// GitHub PAT (classic ghp_ or fine-grained github_pat_)
	{re: regexp.MustCompile(`^(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})$`), label: "GitHub personal access token"},
	// Generic high-entropy hex string (32+ chars: MD5/SHA/UUID-ish secrets).
	// The label claims entropy, so the check measures it: hex tops out at 4
	// bits/char, and a repetitive run like 40 a's is a valid hex string with
	// none of it.
	{
		re:      regexp.MustCompile(`^[0-9a-f]{32,}$`),
		label:   "high-entropy hex string (possible secret)",
		confirm: func(m string) bool { return shannonEntropy(m) >= 3.0 },
	},
}

// looksLikeBase64Secret reports whether a 40-char base64 run is plausibly
// random output rather than a path or an identifier.
//
// Two conditions, both cheap and both necessary. Mixed case with digits is
// what base64 of random bytes looks like and what a lowercase file path
// never is; the entropy floor then rejects the structured strings that
// happen to mix case anyway. The canonical AWS example secret
// (wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY) clears both comfortably.
func looksLikeBase64Secret(match string) bool {
	var hasUpper, hasLower, hasDigit bool
	for _, r := range match {
		switch {
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return false
	}
	return shannonEntropy(match) >= 4.2
}

func (TutorialPatternRule) Check(in FileInput, kb *schema.KnowledgeBase) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		findings = append(findings, checkHardcodedCredentials(in.Path, in.HeadSource, res)...)
		findings = append(findings, checkCredentialValues(in.Path, res)...)
		findings = append(findings, checkOpenCIDR(in.Path, res)...)
		findings = append(findings, checkGenericNaming(in.Path, res)...)
	}

	return findings
}

func checkHardcodedCredentials(path string, src []byte, res *parser.Resource) []report.Finding {
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
		varName := credentialVarName(res, name)
		declaration := fmt.Sprintf("variable %q {\n  type      = string\n  sensitive = true\n}", varName)

		findings = append(findings, report.Finding{
			File:     path,
			Line:     attr.Range.Start.Line,
			Category: report.CategoryTutorialPattern,
			Severity: report.SeverityCritical,
			Resource: res.Address(),
			Message: fmt.Sprintf(
				"%q resolves to a hardcoded string literal%s, not a secret reference — credentials must not be committed in plain text",
				name, viaSuffix(attr)),
			Suggestion: fmt.Sprintf("%s\n\n# in %s:\n%s = var.%s",
				declaration, res.Address(), name, varName),
			Fix: credentialFix(src, attr, name, varName, declaration),
		})
	}
	return findings
}

// credentialFix builds the one-click replacement for a hardcoded credential:
// the same assignment pointing at a sensitive variable instead of a literal.
//
// It returns nil when the literal was reached through a variable default or
// a local (attr.ResolvedFrom is set). In that case the line under the finding
// reads `password = var.db_password` and is already correct — the literal
// lives in the declaration somewhere else, and swapping this line for another
// variable reference would fix nothing while looking like it had.
func credentialFix(src []byte, attr *parser.Attribute, attrName, varName, declaration string) *report.Fix {
	if attr.ResolvedFrom != "" {
		return nil
	}
	start, end, lines, ok := replaceAttrLine(src, attr.Range, attrName,
		fmt.Sprintf("%s = var.%s", attrName, varName))
	if !ok {
		return nil
	}
	return &report.Fix{
		StartLine: start,
		EndLine:   end,
		Lines:     lines,
		// Applying the suggestion alone leaves the variable undeclared, which
		// Terraform rejects at plan time with a clear error. That is a far
		// better failure than a committed password, but it should not come
		// as a surprise — hence the note.
		Note: "This also needs the variable declared, and its value supplied outside the repository " +
			"(TF_VAR_" + varName + ", a tfvars file that isn't committed, or your secret manager):\n\n" +
			"```hcl\n" + declaration + "\n```\n\n" +
			"**The old value is still in this branch's git history — rotate it.**",
	}
}

// viaSuffix names the reference a value was reached through, so a finding
// reported on a line that merely reads `password = var.db_password` says where
// the literal actually lives. Without it the report looks like a false
// positive to whoever opens the file.
func viaSuffix(attr *parser.Attribute) string {
	if attr.ResolvedFrom == "" {
		return ""
	}
	return fmt.Sprintf(" (via %s)", attr.ResolvedFrom)
}

// credentialVarName derives a reasonably unique, valid HCL identifier for
// the suggested variable — resource name + attribute name, since the same
// attribute name (e.g. "password") can recur across multiple resources in
// one file.
func credentialVarName(res *parser.Resource, attrName string) string {
	return sanitizeIdent(res.Name) + "_" + sanitizeIdent(attrName)
}

var nonIdentChar = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func sanitizeIdent(s string) string {
	return nonIdentChar.ReplaceAllString(strings.ToLower(s), "_")
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
			matched := false
			for _, pat := range credentialValuePatterns {
				if patternConfirms(pat.re, pat.confirm, attr.RawValue) {
					findings = append(findings, report.Finding{
						File:     path,
						Line:     attr.Range.Start.Line,
						Category: report.CategoryTutorialPattern,
						Severity: report.SeverityCritical,
						Resource: res.Address(),
						Message: fmt.Sprintf(
							"%s%q value matches pattern: %s%s — remove from source and use a secret reference",
							locationPrefix, name, pat.label, viaSuffix(attr)),
					})
					matched = true
					break // one match per attribute is enough
				}
			}
			if matched {
				continue
			}

			// No known format matched; randomness itself is the fallback
			// signal. High severity rather than critical — this is a
			// statistical accusation, not a recognized credential shape.
			if bits, ok := looksLikeSecret(attr.RawValue); ok {
				findings = append(findings, report.Finding{
					File:     path,
					Line:     attr.Range.Start.Line,
					Category: report.CategoryTutorialPattern,
					Severity: report.SeverityHigh,
					Resource: res.Address(),
					Message: fmt.Sprintf(
						"%s%q value is a high-entropy string (%.1f bits/char over %d chars)%s — this is the statistical signature of a machine-generated secret; if it is one, move it out of source and rotate it",
						locationPrefix, name, bits, len(attr.RawValue), viaSuffix(attr)),
				})
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

// IsCredentialAttrName reports whether name looks like a credential-bearing
// attribute by name alone (password, api_key, token, ...) — exported so
// internal/terragrunt can apply the same check to terragrunt.hcl's
// `inputs`/`remote_state.config` maps, which aren't Terraform resource
// blocks and so never go through parser.Resource.
func IsCredentialAttrName(name string) bool {
	return credentialAttrNames.MatchString(name)
}

// MatchCredentialValuePattern checks value against the same well-known
// credential formats (AWS keys, PEM headers, JWTs, GitHub tokens,
// high-entropy strings) checkCredentialValues uses, regardless of which
// attribute it came from. Returns the matched pattern's human-readable
// label and true, or ("", false) if nothing matched.
func MatchCredentialValuePattern(value string) (label string, ok bool) {
	if len(value) < 16 {
		return "", false
	}
	for _, pat := range credentialValuePatterns {
		if patternConfirms(pat.re, pat.confirm, value) {
			return pat.label, true
		}
	}
	return "", false
}

// patternConfirms reports whether value matches a credential pattern and,
// where the pattern carries one, passes its confirmation check against the
// matched text specifically — not the whole value, since the point is to
// judge the candidate substring the regexp found.
func patternConfirms(re *regexp.Regexp, confirm func(string) bool, value string) bool {
	match := re.FindString(value)
	if match == "" {
		return false
	}
	return confirm == nil || confirm(match)
}

// IsOpenCIDR reports whether value is the wide-open 0.0.0.0/0 CIDR block.
func IsOpenCIDR(value string) bool {
	return value == openCIDR
}
