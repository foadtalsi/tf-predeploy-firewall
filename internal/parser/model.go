package parser

import "github.com/hashicorp/hcl/v2"

// Kind distinguishes the kinds of top-level block this package normalizes.
// They share one Go type because every rule that cares about *values* — a
// hardcoded password, an open CIDR — cares about them identically; only the
// rules that need a provider schema are resource-only.
type Kind string

const (
	// KindResource is a `resource "aws_db_instance" "prod" { … }` block.
	KindResource Kind = "resource"

	// KindModule is a `module "rds" { … }` call. Its arguments are inputs to
	// someone else's module, so there is no schema to validate them against —
	// but a password passed to a module is just as hardcoded as one passed to
	// a resource, and mature Terraform repos are mostly module calls, so
	// ignoring them made the scanner blind exactly where it mattered most.
	KindModule Kind = "module"

	// KindData is a `data "aws_ami" "ubuntu" { … }` block. Data sources read
	// rather than create, so lifecycle and ForceNew rules don't apply, but
	// their arguments can still carry credentials.
	KindData Kind = "data"
)

// Resource is a normalized view of a top-level block, independent of the
// underlying HCL AST so rules don't need to import hclsyntax.
type Resource struct {
	// Kind is what sort of block this came from. Rules that depend on the
	// provider schema (unknown attributes, ForceNew, prevent_destroy) must
	// check this and only act on KindResource.
	Kind Kind

	Type string
	Name string
	File string

	// DefRange is the source range of the block header
	// (used as the fallback location for findings).
	DefRange hcl.Range

	// Attributes maps top-level attribute name -> its value/location.
	Attributes map[string]*Attribute

	// Blocks holds non-lifecycle nested blocks (ingress, egress,
	// root_block_device, environment, vpc_config, …) so rules can
	// inspect attributes inside them (e.g. cidr_blocks in ingress).
	Blocks []*NestedBlock

	HasLifecycleBlock   bool
	PreventDestroyValue *bool // nil if prevent_destroy is absent or not a literal bool
	PreventDestroyRange hcl.Range
}

// NestedBlock is a named sub-block inside a resource body
// (e.g. `ingress { … }`, `root_block_device { … }`).
type NestedBlock struct {
	Type       string
	Labels     []string
	Range      hcl.Range
	Attributes map[string]*Attribute
}

// Attribute is a top-level attribute inside a resource block.
type Attribute struct {
	Name  string
	Range hcl.Range // range of the attribute (name = value) line
	// RawValue holds the literal string form of the expression when it could
	// be statically evaluated (string/number/bool/list of these). Empty if
	// the expression depends on something that can't be resolved.
	RawValue  string
	IsLiteral bool

	// ResolvedFrom names the reference this value came from — "var.db_password",
	// "local.admin_pw" — when the literal was reached by following a variable
	// default or a local rather than being written inline.
	//
	// It exists so a finding can point at where the value actually lives. A
	// report saying `password` is hardcoded, on a line that only reads
	// `password = var.db_password`, otherwise looks like a false positive to
	// the person reading it.
	ResolvedFrom string
}

// Address returns the canonical identifier for the block, matching the
// address Terraform itself would use.
func (r *Resource) Address() string {
	switch r.Kind {
	case KindModule:
		return "module." + r.Name
	case KindData:
		return "data." + r.Type + "." + r.Name
	default:
		return r.Type + "." + r.Name
	}
}
