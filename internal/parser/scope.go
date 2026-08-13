package parser

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/zclconf/go-cty/cty"
)

// Scope resolution: turning `var.x` and `local.y` into the values they carry.
//
// Terraform scopes locals and variables per *directory*, not per file — a
// local declared in locals.tf is visible in rds.tf. BuildScope therefore takes
// every .tf file in one directory and produces a single evaluation context for
// all of them.
//
// What this buys: a password sitting in `variable "db_password" { default =
// "changeme" }` is a hardcoded credential just as much as one written inline,
// and it is the more common mistake of the two. Before this, one level of
// indirection was enough to hide from every value-based rule in the scanner.
//
// What it deliberately does not do is guess. A variable with no default, a
// value from a .tfvars file, anything computed at plan time — all stay
// unresolved, and every rule skips them exactly as before. A richer scope can
// only ever surface more findings, never different ones.

// BuildScope returns an evaluation context for one directory, given the
// contents of its .tf files keyed by path.
//
// Resolution is single-pass: a local defined in terms of another local
// resolves only if the one it depends on was already resolvable on its own.
// Chasing chains would mean implementing Terraform's dependency graph, for a
// case that is rare in the patterns this scanner looks for.
func BuildScope(filesByPath map[string][]byte) *hcl.EvalContext {
	locals := map[string]cty.Value{}
	vars := map[string]cty.Value{}

	for path, src := range filesByPath {
		body, err := parseBody(path, src)
		if err != nil {
			// One unparseable file must not cost us the scope of the rest of
			// the directory; the engine reports that file's parse error itself.
			continue
		}

		for _, block := range body.Blocks {
			switch {
			case block.Type == "locals":
				for name, attr := range block.Body.Attributes {
					if v, diags := attr.Expr.Value(nil); !diags.HasErrors() && v.IsWhollyKnown() {
						locals[name] = v
					}
				}
			case block.Type == "variable" && len(block.Labels) == 1:
				// Only `default` is a value we can know statically. A variable
				// without one is supplied at plan time, so it stays unknown.
				def, ok := block.Body.Attributes["default"]
				if !ok {
					continue
				}
				if v, diags := def.Expr.Value(nil); !diags.HasErrors() && v.IsWhollyKnown() {
					vars[block.Labels[0]] = v
				}
			}
		}
	}

	if len(locals) == 0 && len(vars) == 0 {
		return nil
	}

	variables := map[string]cty.Value{}
	if len(locals) > 0 {
		variables["local"] = cty.ObjectVal(locals)
	}
	if len(vars) > 0 {
		variables["var"] = cty.ObjectVal(vars)
	}
	return &hcl.EvalContext{Variables: variables}
}
