// Package terragrunt scans terragrunt.hcl files — Terragrunt's own config
// format, not a .tf resource file — for the same hardcoded-credential and
// open-CIDR patterns TutorialPatternRule already catches inside Terraform
// resource blocks. Terragrunt's `inputs` map (and `remote_state.config`)
// commonly carries exactly the kind of secret this tool exists to catch,
// but every terragrunt.hcl file was previously invisible to the scanner
// entirely: it only ever considered files ending in .tf.
package terragrunt

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/rules"
)

// ScanFile scans one terragrunt.hcl file's `inputs` map and
// `remote_state.config` map for hardcoded credentials and open CIDRs.
// A parse error is returned to the caller (same convention as
// parser.ParseFile) rather than silently skipping the file.
func ScanFile(path string, src []byte) ([]report.Finding, error) {
	file, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("hcl parse error in %s: %s", path, diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected body type for %s", path)
	}

	var findings []report.Finding

	if attr, ok := body.Attributes["inputs"]; ok {
		findings = append(findings, scanMapExpr(path, "inputs", attr.Expr)...)
	}
	for _, block := range body.Blocks {
		if block.Type != "remote_state" {
			continue
		}
		if attr, ok := block.Body.Attributes["config"]; ok {
			findings = append(findings, scanMapExpr(path, "remote_state.config", attr.Expr)...)
		}
	}

	return findings, nil
}

// scanMapExpr walks an object-constructor expression (e.g. the value of
// `inputs = { ... }`) key by key, recursing into nested maps, and flags
// any string leaf value that looks like a hardcoded credential or an open
// CIDR block. Expressions that reference a variable/local/function (can't
// be evaluated with a nil EvalContext) are skipped, same "no plan, no
// state, only statically-resolvable values" philosophy as internal/parser.
func scanMapExpr(path, keyPath string, expr hcl.Expression) []report.Finding {
	pairs, diags := hcl.ExprMap(expr)
	if diags.HasErrors() {
		return nil // not a map/object literal — nothing further to inspect here
	}

	var findings []report.Finding
	for _, pair := range pairs {
		keyName := exprKeyString(pair.Key)
		fullKey := keyPath
		if keyName != "" {
			fullKey = keyPath + "." + keyName
		}

		if _, nestedDiags := hcl.ExprMap(pair.Value); !nestedDiags.HasErrors() {
			findings = append(findings, scanMapExpr(path, fullKey, pair.Value)...)
			continue
		}

		v, vdiags := pair.Value.Value(nil)
		if vdiags.HasErrors() || v.IsNull() || v.Type() != cty.String {
			continue
		}
		strVal := v.AsString()
		line := pair.Value.Range().Start.Line

		if keyName != "" && strVal != "" && rules.IsCredentialAttrName(keyName) {
			findings = append(findings, report.Finding{
				File: path, Line: line, Category: report.CategoryTutorialPattern, Severity: report.SeverityCritical,
				Resource: keyPath,
				Message: fmt.Sprintf(
					"%s is a hardcoded string literal, not a variable or secret reference — credentials must not be committed in plain text", fullKey),
			})
			continue
		}
		if label, ok := rules.MatchCredentialValuePattern(strVal); ok {
			findings = append(findings, report.Finding{
				File: path, Line: line, Category: report.CategoryTutorialPattern, Severity: report.SeverityCritical,
				Resource: keyPath,
				Message:  fmt.Sprintf("%s value matches pattern: %s — remove from source and use a secret reference", fullKey, label),
			})
			continue
		}
		if rules.IsOpenCIDR(strVal) {
			findings = append(findings, report.Finding{
				File: path, Line: line, Category: report.CategoryTutorialPattern, Severity: report.SeverityHigh,
				Resource: keyPath,
				Message:  fmt.Sprintf(`%s = "0.0.0.0/0" allows traffic from anywhere`, fullKey),
			})
		}
	}
	return findings
}

// exprKeyString extracts a map key's literal name. Bare identifier keys
// (inputs = { db_password = "x" }) surface as a keyword-like traversal;
// quoted keys ("db-password" = "x") are string literals. Returns "" if
// neither form applies (a computed key expression), in which case the
// caller still inspects the value, just without a dotted key in messages.
func exprKeyString(keyExpr hcl.Expression) string {
	if kw := hcl.ExprAsKeyword(keyExpr); kw != "" {
		return kw
	}
	v, diags := keyExpr.Value(nil)
	if diags.HasErrors() || v.Type() != cty.String {
		return ""
	}
	return v.AsString()
}
