// Package tfvars scans .tfvars files — Terraform's variable-value files,
// not resource definitions — for the same hardcoded-credential patterns
// TutorialPatternRule catches inside resource blocks.
//
// This closes the widest gap between what the tool claimed and what it did.
// A .tfvars file is, by design, the place values live: someone told to move
// a password out of main.tf will very often move it into terraform.tfvars
// and commit that instead. The scanner's own suggested fix says to use "a
// tfvars file that isn't committed" — while never checking whether one is.
//
// Only committed files reach this code. The scanner sources its file list
// from git (a ref diff, the index, or `ls-files --exclude-standard`), so a
// .tfvars that is properly gitignored is never seen — which is exactly
// right: the finding is "this secret is in the repository", and a file git
// ignores isn't.
package tfvars

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/rules"
)

// IsTfvarsPath reports whether a path is a Terraform variable-values file:
// terraform.tfvars, anything.auto.tfvars, and their .json forms.
func IsTfvarsPath(path string) bool {
	return strings.HasSuffix(path, ".tfvars") || strings.HasSuffix(path, ".tfvars.json")
}

// ScanFile scans one .tfvars (or .tfvars.json) file for hardcoded
// credentials and open CIDR blocks.
//
// A parse error is returned rather than swallowed, same convention as
// parser.ParseFile: a .tfvars file the scanner cannot read is a gap the
// caller should report, not one it should hide.
func ScanFile(path string, src []byte) ([]report.Finding, error) {
	if strings.HasSuffix(path, ".json") {
		return scanJSON(path, src)
	}
	return scanHCL(path, src)
}

func scanHCL(path string, src []byte) ([]report.Finding, error) {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("hcl parse error in %s: %s", path, diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected body type for %s", path)
	}

	// A .tfvars file is a flat list of `name = value` assignments; it
	// declares no blocks. Anything block-shaped is not a variable
	// assignment and has no value to judge.
	var findings []report.Finding
	for name, attr := range body.Attributes {
		findings = append(findings, scanValue(path, name, attr.Expr, attr.SrcRange.Start.Line)...)
	}
	return findings, nil
}

// scanValue evaluates one variable's value and judges it, recursing into
// objects and tuples so a credential nested inside a map of settings is
// found too.
//
// Values that reference anything (a function call, another variable) can't
// be evaluated statically and are skipped — the same rule the rest of the
// tool follows: never guess at a value, because a guess is how a false
// positive gets in.
func scanValue(path, name string, expr hclsyntax.Expression, line int) []report.Finding {
	v, diags := expr.Value(nil)
	if diags.HasErrors() || v.IsNull() || !v.IsWhollyKnown() {
		return nil
	}
	return judge(path, name, v, line)
}

func judge(path, name string, v cty.Value, line int) []report.Finding {
	t := v.Type()

	switch {
	case t.IsObjectType(), t.IsMapType():
		var out []report.Finding
		for k, elem := range v.AsValueMap() {
			// The nested key is what names the secret, but the finding is
			// reported against the top-level variable path so the reader
			// can find it: "database.password", not a bare "password".
			out = append(out, judge(path, name+"."+k, elem, line)...)
		}
		return out

	case t.IsTupleType(), t.IsListType(), t.IsSetType():
		var out []report.Finding
		for _, elem := range v.AsValueSlice() {
			out = append(out, judge(path, name, elem, line)...)
		}
		return out

	case t == cty.String:
		return judgeString(path, name, v.AsString(), line)
	}
	return nil
}

func judgeString(path, name, value string, line int) []report.Finding {
	if value == "" {
		return nil
	}

	// The attribute name is the last path segment: for `db = { password =
	// "x" }` the credential-ness lives in "password", not in "db.password".
	leaf := name
	if i := strings.LastIndex(leaf, "."); i >= 0 {
		leaf = leaf[i+1:]
	}

	finding := func(severity report.Severity, msg string) []report.Finding {
		return []report.Finding{{
			File:     path,
			Line:     line,
			Category: report.CategoryTutorialPattern,
			Severity: severity,
			Resource: name,
			Message:  msg,
		}}
	}

	// Wording note: the same scan runs pre-commit (--staged/--uncommitted)
	// and on a PR, and the right advice differs. Before the commit the fix
	// is simply "don't"; after it, the value is disclosed and deleting the
	// line does not undo that. Saying "already committed" would be wrong in
	// the first case and saying nothing about rotation would be negligent
	// in the second, so the rotation clause is stated as the condition it
	// actually is.
	const remedy = " — variable values belong outside the repository (a TF_VAR_ environment variable, a gitignored tfvars file, or your secret manager). If this file is already committed, the value is disclosed: rotate it."

	if rules.IsCredentialAttrName(leaf) {
		return finding(report.SeverityCritical,
			fmt.Sprintf("%q is a hardcoded credential in a .tfvars file", name)+remedy)
	}
	if label, ok := rules.MatchCredentialValuePattern(value); ok {
		return finding(report.SeverityCritical,
			fmt.Sprintf("%q matches pattern: %s", name, label)+remedy)
	}
	if rules.IsOpenCIDR(value) {
		return finding(report.SeverityHigh, fmt.Sprintf(
			"%q is %s, open to the entire internet — narrow this range", name, value))
	}
	if bits, ok := rules.LooksLikeSecret(value); ok {
		return finding(report.SeverityHigh, fmt.Sprintf(
			"%q is a high-entropy string (%.1f bits/char over %d chars) — the statistical signature of a machine-generated secret; if it is one%s",
			name, bits, len(value), remedy))
	}
	return nil
}

// scanJSON handles the .tfvars.json form, which automation tends to
// generate and which the HCL parser cannot read.
func scanJSON(path string, src []byte) ([]report.Finding, error) {
	var doc map[string]any
	if err := json.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("json parse error in %s: %w", path, err)
	}

	var findings []report.Finding
	for name, v := range doc {
		findings = append(findings, judgeJSON(path, name, v)...)
	}
	return findings, nil
}

// judgeJSON mirrors judge for decoded JSON. Line 1 throughout: encoding/json
// discards positions, and reporting a wrong line would be worse than
// reporting the file — the variable name in the message is what locates it.
func judgeJSON(path, name string, v any) []report.Finding {
	switch t := v.(type) {
	case string:
		return judgeString(path, name, t, 1)
	case map[string]any:
		var out []report.Finding
		for k, elem := range t {
			out = append(out, judgeJSON(path, name+"."+k, elem)...)
		}
		return out
	case []any:
		var out []report.Finding
		for _, elem := range t {
			out = append(out, judgeJSON(path, name, elem)...)
		}
		return out
	}
	return nil
}
