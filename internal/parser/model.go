package parser

import "github.com/hashicorp/hcl/v2"

// Resource is a normalized view of a `resource "type" "name" { ... }` block,
// independent of the underlying HCL AST so rules don't need to import hclsyntax.
type Resource struct {
	Type string
	Name string
	File string

	// DefRange is the source range of the resource block header
	// (used as the fallback location for findings).
	DefRange hcl.Range

	// Attributes maps top-level attribute name -> its value/location.
	Attributes map[string]*Attribute

	HasLifecycleBlock   bool
	PreventDestroyValue *bool // nil if prevent_destroy is absent or not a literal bool
	PreventDestroyRange hcl.Range
}

// Attribute is a top-level attribute inside a resource block.
type Attribute struct {
	Name  string
	Range hcl.Range // range of the attribute (name = value) line
	// RawValue holds the literal string form of the expression when it could
	// be statically evaluated (string/number/bool/list of these). Empty if
	// the expression depends on a variable/reference and can't be evaluated.
	RawValue string
	IsLiteral bool
}

// Address returns the canonical "type.name" identifier for the resource.
func (r *Resource) Address() string {
	return r.Type + "." + r.Name
}
