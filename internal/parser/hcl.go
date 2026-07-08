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

// ParseFile parses a single .tf file's contents and returns the resource
// blocks it declares. Diagnostics from malformed HCL are returned as an
// error; callers should treat parse failures as a finding of their own
// rather than crashing the whole scan.
func ParseFile(filename string, src []byte) ([]*Resource, error) {
	parser := hclparseNew()
	file, diags := parser.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("hcl parse error in %s: %s", filename, diags.Error())
	}

	body, ok := file.Body.(*hclsyntax.Body)
	if !ok {
		return nil, fmt.Errorf("unexpected body type for %s", filename)
	}

	var resources []*Resource
	for _, block := range body.Blocks {
		if block.Type != "resource" || len(block.Labels) != 2 {
			continue
		}
		resources = append(resources, blockToResource(filename, block))
	}
	return resources, nil
}

func blockToResource(filename string, block *hclsyntax.Block) *Resource {
	r := &Resource{
		Type:       block.Labels[0],
		Name:       block.Labels[1],
		File:       filename,
		DefRange:   block.DefRange(),
		Attributes: map[string]*Attribute{},
	}

	for name, attr := range block.Body.Attributes {
		r.Attributes[name] = attrToAttribute(name, attr)
	}

	for _, nested := range block.Body.Blocks {
		if nested.Type == "lifecycle" {
			r.HasLifecycleBlock = true
			if pdAttr, ok := nested.Body.Attributes["prevent_destroy"]; ok {
				r.PreventDestroyRange = pdAttr.SrcRange
				if v, diags := pdAttr.Expr.Value(nil); !diags.HasErrors() && v.Type() == cty.Bool {
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
		for name, attr := range nested.Body.Attributes {
			nb.Attributes[name] = attrToAttribute(name, attr)
		}
		r.Blocks = append(r.Blocks, nb)
	}

	return r
}

func attrToAttribute(name string, attr *hclsyntax.Attribute) *Attribute {
	a := &Attribute{
		Name:  name,
		Range: attr.SrcRange,
	}

	v, diags := attr.Expr.Value(nil)
	if diags.HasErrors() {
		// Expression references a variable/resource/function we can't
		// resolve statically (no plan, no state). Leave RawValue empty;
		// rules that need a literal value will simply skip this attribute.
		return a
	}

	a.IsLiteral = true
	a.RawValue = ctyValueToString(v)
	return a
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

func hclparseNew() *hclparseWrapper {
	return &hclparseWrapper{}
}

// hclparseWrapper avoids importing hclparse's file-cache semantics (which
// key by filename and would collide across base/head revisions of the same
// path); we parse byte slices directly instead.
type hclparseWrapper struct{}

func (w *hclparseWrapper) ParseHCL(src []byte, filename string) (*hcl.File, hcl.Diagnostics) {
	return hclsyntax.ParseConfig(src, filename, hcl.InitialPos)
}
