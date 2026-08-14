package rules

import (
	"regexp"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
)

// The tutorial-pattern detectors — hardcoded credentials, wide-open CIDRs,
// placeholder naming — used to live here as Go. They are now declarations in
// internal/ruledef/rules.yaml, evaluated by declarativeRule.
//
// What stayed behind is what a rule file names but cannot contain: the
// helpers that build a finding's text from what was matched. They are
// primitives, not content — no pattern, no severity and no wording is
// decided here.

// viaSuffix names the reference a value was reached through, so a finding
// reported on a line that merely reads `password = var.db_password` says
// where the literal actually lives. Without it the report looks like a false
// positive to whoever opens the file.
func viaSuffix(attr *parser.Attribute) string {
	if attr.ResolvedFrom == "" {
		return ""
	}
	return " (via " + attr.ResolvedFrom + ")"
}

// credentialVarName derives a reasonably unique, valid HCL identifier for
// the variable a fix suggests — resource name plus attribute name, since the
// same attribute name (`password`) recurs across resources in one file.
//
// blockType is the nested block the attribute sits in, and joins the name
// when there is one: a resource can hold two blocks declaring the same
// attribute, and suggesting the same variable for both would have the second
// fix quietly overwrite the first one's meaning.
func credentialVarName(res *parser.Resource, blockType, attrName string) string {
	name := sanitizeIdent(res.Name)
	if blockType != "" {
		name += "_" + sanitizeIdent(blockType)
	}
	return name + "_" + sanitizeIdent(attrName)
}

var nonIdentChar = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func sanitizeIdent(s string) string {
	return nonIdentChar.ReplaceAllString(strings.ToLower(s), "_")
}
