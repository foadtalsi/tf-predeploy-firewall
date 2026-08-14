package rules

import "regexp"

// Message templating for declarative rules.
//
// A fixed set of `{placeholder}` tokens, substituted from what the matcher
// found. Deliberately not an expression language: a rule file decides the
// wording, not the control flow, and the moment a template can compute it
// stops being data.

// templateToken also matches a `${…}` so it can decline to substitute one.
// Rule text is HCL-adjacent — a fix that writes an interpolation would
// otherwise have its inner braces eaten.
var templateToken = regexp.MustCompile(`\$?\{([a-z_]+)\}`)

// expand substitutes known tokens and leaves everything else byte for byte.
//
// Unknown tokens survive untouched on purpose: fix and suggestion templates
// contain literal HCL braces (`variable "x" {`), and a templater that
// swallowed or errored on them could not write Terraform.
func expand(tmpl string, vars map[string]string) string {
	if tmpl == "" {
		return ""
	}
	return templateToken.ReplaceAllStringFunc(tmpl, func(tok string) string {
		if tok[0] == '$' {
			return tok // an interpolation, not a placeholder
		}
		if v, ok := vars[tok[1:len(tok)-1]]; ok {
			return v
		}
		return tok
	})
}

// expandAll applies expand to a slice, for multi-line fix bodies.
func expandAll(tmpls []string, vars map[string]string) []string {
	out := make([]string, len(tmpls))
	for i, t := range tmpls {
		out[i] = expand(t, vars)
	}
	return out
}
