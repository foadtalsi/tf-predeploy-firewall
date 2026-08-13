// Package parser wraps hashicorp/hcl (the parser Terraform itself uses) to
// turn raw .tf source into a normalized slice of Resource values that the
// rule engine can inspect without touching the HCL AST directly.
package parser

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// ParseFile parses a single .tf file's contents and returns the blocks it
// declares — resources, module calls and data sources. Diagnostics from
// malformed HCL are returned as an error; callers should treat parse failures
// as a finding of their own rather than crashing the whole scan.
func ParseFile(filename string, src []byte) ([]*Resource, error) {
	return ParseFileWithContext(filename, src, nil)
}

// ParseFileWithContext is ParseFile with a scope for resolving references.
//
// Without a context, `password = var.db_password` is simply unresolvable and
// every rule skips it. With one built from the surrounding directory's
// `locals` blocks and `variable` defaults (see BuildScope), that same line
// resolves to the value it will actually carry — which is how a password left
// in a variable default gets caught instead of hiding one indirection away.
//
// A reference the scope can't resolve stays unresolved rather than guessed,
// so a richer scope only ever finds more, never differently.
func ParseFileWithContext(filename string, src []byte, ctx *hcl.EvalContext) ([]*Resource, error) {
	body, err := parseBody(filename, src)
	if err != nil {
		return nil, err
	}

	var resources []*Resource
	for _, block := range body.Blocks {
		switch {
		case block.Type == "resource" && len(block.Labels) == 2:
			resources = append(resources, blockToResource(filename, block, KindResource, block.Labels[0], block.Labels[1], ctx))
		case block.Type == "data" && len(block.Labels) == 2:
			resources = append(resources, blockToResource(filename, block, KindData, block.Labels[0], block.Labels[1], ctx))
		case block.Type == "module" && len(block.Labels) == 1:
			// A module call has no type of its own; "module" stands in so
			// schema-driven rules, which look types up in a provider pack,
			// find nothing and skip it.
			resources = append(resources, blockToResource(filename, block, KindModule, "module", block.Labels[0], ctx))
		}
	}
	return resources, nil
}

func parseBody(filename string, src []byte) (*hclsyntax.Body, error) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("hcl parse error in %s: %s", filename, diags.Error())
	}
	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected body type for %s", filename)
	}
	return body, nil
}

func blockToResource(filename string, block *hclsyntax.Block, kind Kind, typeName, name string, ctx *hcl.EvalContext) *Resource {
	r := &Resource{
		Kind:       kind,
		Type:       typeName,
		Name:       name,
		File:       filename,
		DefRange:   block.DefRange(),
		Attributes: map[string]*Attribute{},
	}

	for attrName, attr := range block.Body.Attributes {
		r.Attributes[attrName] = attrToAttribute(attrName, attr, ctx)
	}

	for _, nested := range block.Body.Blocks {
		if nested.Type == "lifecycle" {
			r.HasLifecycleBlock = true
			r.LifecycleRange = nested.DefRange()
			if pdAttr, ok := nested.Body.Attributes["prevent_destroy"]; ok {
				r.PreventDestroyRange = pdAttr.SrcRange
				if v, diags := pdAttr.Expr.Value(ctx); !diags.HasErrors() && v.Type() == cty.Bool {
					b := v.True()
					r.PreventDestroyValue = &b
				}
			}
			continue
		}
		nb := &NestedBlock{
			Type:       nested.Type,
			Labels:     nested.Labels,
			Range:      nested.DefRange(),
			Attributes: map[string]*Attribute{},
		}
		for attrName, attr := range nested.Body.Attributes {
			nb.Attributes[attrName] = attrToAttribute(attrName, attr, ctx)
		}
		r.Blocks = append(r.Blocks, nb)
	}

	return r
}

func attrToAttribute(name string, attr *hclsyntax.Attribute, ctx *hcl.EvalContext) *Attribute {
	a := &Attribute{
		Name:  name,
		Range: attr.SrcRange,
	}

	// Try the expression on its own first. If that works the value was written
	// inline, and there is no indirection worth reporting.
	if v, diags := attr.Expr.Value(nil); !diags.HasErrors() {
		a.IsLiteral = true
		a.RawValue = ctyValueToString(v)
		return a
	}

	if ctx == nil {
		// Expression references a variable/resource/function we can't resolve
		// (no plan, no state). Leave RawValue empty; rules that need a literal
		// value will simply skip this attribute.
		return a
	}

	v, diags := attr.Expr.Value(ctx)
	if diags.HasErrors() || !v.IsWhollyKnown() {
		return a
	}
	a.IsLiteral = true
	a.RawValue = ctyValueToString(v)
	a.ResolvedFrom = firstTraversalName(attr.Expr)
	return a
}

// firstTraversalName renders the reference an expression reads from, e.g.
// "var.db_password" or "local.admin_pw", for use in a finding message.
func firstTraversalName(expr hclsyntax.Expression) string {
	for _, traversal := range expr.Variables() {
		name := ""
		for i, step := range traversal {
			switch t := step.(type) {
			case hcl.TraverseRoot:
				name = t.Name
			case hcl.TraverseAttr:
				name += "." + t.Name
			default:
				// An index or splat: the root is still the useful part.
			}
			if i > 1 {
				break
			}
		}
		if name != "" {
			return name
		}
	}
	return ""
}

// ctyValueToString renders a literal cty.Value as plain text for pattern
// matching (e.g. comparing ForceNew attribute values across revisions, or
// regex-matching against "0.0.0.0/0").
func ctyValueToString(v cty.Value) string {
	if v.IsNull() {
		return ""
	}
	switch {
	case v.Type() == cty.String:
		return v.AsString()
	case v.Type() == cty.Bool:
		if v.True() {
			return "true"
		}
		return "false"
	case v.Type() == cty.Number:
		return v.AsBigFloat().String()
	case v.Type().IsListType(), v.Type().IsTupleType(), v.Type().IsSetType():
		out := ""
		it := v.ElementIterator()
		for it.Next() {
			_, ev := it.Element()
			if out != "" {
				out += ","
			}
			out += ctyValueToString(ev)
		}
		return out
	default:
		return ""
	}
}
