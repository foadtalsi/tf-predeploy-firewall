// Package ruledef holds the declarative rule format: what a rule looks for,
// how the finding is worded, which compiled predicate confirms it, and the
// long-form documentation a reader sees on an alert page.
//
// Rules are data. This package deliberately imports nothing from the rest of
// the scanner — not the parser, not the report types — so that the format
// stays independent of the engine that evaluates it. Anything that can read
// YAML can read a rule pack, which is the whole point: contributing a
// detection pattern must not require a Go toolchain, and shipping one must
// not require a release.
//
// What is NOT expressible here is as deliberate as what is. There is no
// expression language and no way to call out to code. A rule names a
// predicate from a fixed vocabulary the binary provides (entropy floors,
// base64 randomness, HCL fix surgery) and that vocabulary is the only thing
// a rule can invoke. The scanner runs inside other people's CI pipelines;
// "customers can write code that executes here" is not a trade worth taking
// for a convenience feature.
package ruledef

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// FormatVersion is the rule-pack format this binary understands. A pack
// declaring a newer version is refused rather than partially interpreted:
// a rule whose semantics the reader does not implement is a rule that
// silently matches nothing, which looks exactly like a clean scan.
const FormatVersion = 1

// Pack is a full set of rules, as loaded from YAML.
type Pack struct {
	Version int     `yaml:"version"`
	Rules   []*Rule `yaml:"rules"`

	// Docs is keyed by category rather than by rule because that is the
	// granularity a reader meets it at: a code-scanning alert page shows one
	// explanation per category, and the seven credential-format detectors all
	// report as tutorial_pattern. Attaching prose per rule would mean seven
	// copies of the same page, or an arbitrary rule owning it.
	Docs []*CategoryDoc `yaml:"docs,omitempty"`

	// Anchors is never read. It exists so a pack can define YAML anchors in
	// one declared place and alias them into the rules below, instead of
	// repeating a shared pattern once per rule and watching the copies drift.
	// Declaring the key rather than relying on unknown-field tolerance means
	// a reader of this struct can see why the section is there.
	Anchors map[string]any `yaml:"anchors,omitempty"`

	byID    map[string]*Rule
	byGroup map[string][]*Rule
	byCat   map[string]*CategoryDoc
	groups  []string // group names in first-appearance order
}

// CategoryDoc is the long-form explanation of one category, rendered on a
// code-scanning alert page and in docs/rules.md — read by someone who did
// not run the scan and has no context for it. A category that cannot explain
// itself there is one that gets switched off wholesale rather than tuned.
type CategoryDoc struct {
	Category        string `yaml:"category"`
	Title           string `yaml:"title"`
	FullDescription string `yaml:"full_description"`
	Markdown        string `yaml:"markdown"`
}

// Rule is one detector, or one compiled detector's metadata.
type Rule struct {
	ID       string `yaml:"id"`
	Category string `yaml:"category"`
	Severity string `yaml:"severity"`

	// Engine names a compiled detector that owns this rule's traversal, for
	// checks a declarative matcher cannot express: schema lookups, base
	// versus head comparison, brace-matched source scanning. The rule still
	// owns its severity, wording and documentation — only the walk is code.
	//
	// Empty means the rule is fully declarative and Match drives it.
	Engine string `yaml:"engine,omitempty"`

	// Group ties ordered alternatives together. Within one group the first
	// rule to match a given location wins and the rest are skipped, which is
	// how a specific credential format takes precedence over the generic
	// entropy fallback that would otherwise also fire on it.
	Group string `yaml:"group,omitempty"`

	// Label is the human-readable name of what matched ("JWT token"),
	// substituted into messages as {label} and returned by the exported
	// value-matching helpers.
	Label string `yaml:"label,omitempty"`

	Match *Match `yaml:"match,omitempty"`

	Message    string `yaml:"message"`
	Suggestion string `yaml:"suggestion,omitempty"`
	Fix        *Fix   `yaml:"fix,omitempty"`

	// Params carries engine-specific settings. Kept as strings so the format
	// has one scalar type and no schema-per-engine.
	Params map[string]string `yaml:"params,omitempty"`
}

// Match is the declarative condition. Every field set must hold; an empty
// Match matches nothing, which validation rejects rather than silently
// flagging every resource in the repository.
type Match struct {
	// Scope selects what is walked:
	//   attribute       — a resource's top-level attributes
	//   block_attribute — attributes inside nested blocks
	//   any_attribute   — both
	//   resource_name   — the resource's local name (the second label)
	Scope string `yaml:"scope"`

	// Kinds restricts to resource / data / module blocks. Empty means any.
	Kinds []string `yaml:"kinds,omitempty"`

	// ResourceTypes lists exact provider type names; empty means any.
	ResourceTypes []string `yaml:"resource_types,omitempty"`

	// BlockTypes restricts which nested blocks are walked; empty means all.
	BlockTypes []string `yaml:"block_types,omitempty"`

	AttrNames          []string `yaml:"attr_names,omitempty"`
	AttrNameMatches    string   `yaml:"attr_name_matches,omitempty"`
	AttrNameNotMatches string   `yaml:"attr_name_not_matches,omitempty"`
	AttrNameContains   string   `yaml:"attr_name_contains,omitempty"`

	// Literal requires the value to be statically known. A non-literal is an
	// expression the scanner cannot evaluate, and guessing at one is how a
	// rule earns a reputation for false positives.
	Literal   *bool `yaml:"literal,omitempty"`
	MinLength int   `yaml:"min_length,omitempty"`

	ValueMatches  string   `yaml:"value_matches,omitempty"`
	ValueContains string   `yaml:"value_contains,omitempty"`
	ValueNotOneOf []string `yaml:"value_not_one_of,omitempty"`

	// NameMatches applies to scope: resource_name.
	NameMatches string `yaml:"name_matches,omitempty"`

	// Confirm names a predicate applied to the substring ValueMatches found,
	// not to the whole value: the point is to judge the candidate the regex
	// picked out. This is what separates a 40-character secret from a
	// 40-character file path.
	Confirm string `yaml:"confirm,omitempty"`

	// Predicate names a predicate applied to the whole value, for detectors
	// that are a measurement rather than a shape.
	Predicate string `yaml:"predicate,omitempty"`

	attrName    *regexp.Regexp
	attrNameNot *regexp.Regexp
	value       *regexp.Regexp
	name        *regexp.Regexp
}

// Fix describes the one-click replacement offered with a finding.
type Fix struct {
	// Action names the compiled source-surgery primitive. The text has to
	// reproduce the surrounding lines byte for byte, which is why this is a
	// named operation rather than anything the YAML spells out itself.
	//   replace_attr_line — swap the matched attribute's line
	//   insert_into_block — add lines just inside a block header
	Action string `yaml:"action"`

	// Lines is the replacement or inserted text, templated.
	Lines []string `yaml:"lines"`

	// Note is shown with the suggestion, for the part applying it does not
	// do. A fix that leaves the tree in a state the author did not expect
	// has to say so.
	Note string `yaml:"note,omitempty"`

	// SkipWhenResolved withholds the fix when the value was reached through
	// a variable or local rather than written inline. The line under the
	// finding is then already correct and rewriting it would fix nothing
	// while looking like it had.
	SkipWhenResolved bool `yaml:"skip_when_resolved,omitempty"`
}

var validSeverities = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

var validScopes = map[string]bool{
	"attribute": true, "block_attribute": true, "any_attribute": true,
	"resource_name": true,
}

// Only the one action, because it is the only one a declarative rule can
// currently reach: every declarative scope resolves to an attribute, and an
// attribute has a line to overwrite but no block header to insert beneath.
// Block insertion exists as a primitive (missing_lifecycle writes a whole
// lifecycle block with it) and stays compiled until a scope that can address
// a block header exists. Listing it here before then would let a pack ask
// for a fix that silently never appears.
var validFixActions = map[string]bool{
	"replace_attr_line": true,
}

// Load parses and fully validates a rule pack. Every regex is compiled and
// every enum checked at load time, so a typo fails the scan loudly instead
// of producing a rule that quietly matches nothing.
func Load(data []byte) (*Pack, error) {
	var p Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing rule pack: %w", err)
	}
	if p.Version == 0 {
		return nil, fmt.Errorf("rule pack has no version field")
	}
	if p.Version > FormatVersion {
		return nil, fmt.Errorf(
			"rule pack declares format version %d but this binary understands %d — upgrade the scanner rather than running it against a pack it can only partly read",
			p.Version, FormatVersion)
	}
	if len(p.Rules) == 0 {
		return nil, fmt.Errorf("rule pack declares no rules")
	}

	p.byID = make(map[string]*Rule, len(p.Rules))
	p.byGroup = map[string][]*Rule{}
	p.byCat = make(map[string]*CategoryDoc, len(p.Docs))

	for i, d := range p.Docs {
		if d.Category == "" {
			return nil, fmt.Errorf("docs %d: category is required", i)
		}
		if _, dup := p.byCat[d.Category]; dup {
			return nil, fmt.Errorf("docs %d: duplicate category %q", i, d.Category)
		}
		p.byCat[d.Category] = d
	}

	for i, r := range p.Rules {
		if err := r.validate(); err != nil {
			return nil, fmt.Errorf("rule %d (%s): %w", i, r.ID, err)
		}
		if _, dup := p.byID[r.ID]; dup {
			return nil, fmt.Errorf("rule %d: duplicate id %q", i, r.ID)
		}
		p.byID[r.ID] = r
		if r.Group != "" {
			if _, seen := p.byGroup[r.Group]; !seen {
				p.groups = append(p.groups, r.Group)
			}
			p.byGroup[r.Group] = append(p.byGroup[r.Group], r)
		}
	}

	// Alternatives only take precedence over one another if they are looking
	// at the same thing. A group whose members walk different scopes would
	// have first-match-wins semantics that depend on which rule happened to
	// see a location first.
	for name, group := range p.byGroup {
		scope := ""
		for _, r := range group {
			if r.Match == nil {
				return nil, fmt.Errorf("rule %q: a grouped rule must be declarative (group %q)", r.ID, name)
			}
			if scope == "" {
				scope = r.Match.Scope
				continue
			}
			if r.Match.Scope != scope {
				return nil, fmt.Errorf(
					"group %q mixes scopes (%s and %s) — first-match-wins is only meaningful between rules that examine the same location",
					name, scope, r.Match.Scope)
			}
		}
	}

	return &p, nil
}

func (r *Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if r.Category == "" {
		return fmt.Errorf("category is required")
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("severity must be one of low/medium/high/critical, got %q", r.Severity)
	}
	if r.Engine == "" && r.Match == nil {
		return fmt.Errorf("a rule needs either an engine or a match block")
	}
	if r.Engine != "" && r.Match != nil {
		return fmt.Errorf("engine and match are mutually exclusive — a compiled engine owns its own traversal")
	}
	if r.Match != nil && r.Message == "" {
		return fmt.Errorf("message is required")
	}
	if r.Match != nil {
		if err := r.Match.validate(); err != nil {
			return err
		}
	}
	if r.Fix != nil {
		if r.Match == nil {
			return fmt.Errorf("fix is only meaningful on a declarative rule")
		}
		if !validFixActions[r.Fix.Action] {
			return fmt.Errorf("fix action must be replace_attr_line or insert_into_block, got %q", r.Fix.Action)
		}
		if len(r.Fix.Lines) == 0 {
			return fmt.Errorf("fix has no lines")
		}
	}
	return nil
}

func (m *Match) validate() error {
	if !validScopes[m.Scope] {
		return fmt.Errorf("match scope must be one of attribute/block_attribute/any_attribute/resource_name, got %q", m.Scope)
	}
	if m.Scope == "resource_name" && m.NameMatches == "" {
		return fmt.Errorf("scope resource_name needs name_matches")
	}
	if m.Scope != "resource_name" && !m.hasAttrCondition() {
		return fmt.Errorf("an attribute-scoped rule needs at least one condition — a match block with none would flag every attribute in the repository")
	}
	if m.Confirm != "" && m.ValueMatches == "" {
		return fmt.Errorf("confirm applies to the text value_matches found, so value_matches is required with it")
	}

	var err error
	if m.attrName, err = compileOpt(m.AttrNameMatches); err != nil {
		return fmt.Errorf("attr_name_matches: %w", err)
	}
	if m.attrNameNot, err = compileOpt(m.AttrNameNotMatches); err != nil {
		return fmt.Errorf("attr_name_not_matches: %w", err)
	}
	if m.value, err = compileOpt(m.ValueMatches); err != nil {
		return fmt.Errorf("value_matches: %w", err)
	}
	if m.name, err = compileOpt(m.NameMatches); err != nil {
		return fmt.Errorf("name_matches: %w", err)
	}
	return nil
}

func (m *Match) hasAttrCondition() bool {
	return len(m.AttrNames) > 0 || m.AttrNameMatches != "" || m.AttrNameNotMatches != "" ||
		m.AttrNameContains != "" || m.Literal != nil || m.MinLength > 0 ||
		m.ValueMatches != "" || m.ValueContains != "" || len(m.ValueNotOneOf) > 0 ||
		m.Predicate != ""
}

func compileOpt(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	return regexp.Compile(pattern)
}

// Compiled accessors, so the evaluator never recompiles a pattern per file.

func (m *Match) AttrNameRE() *regexp.Regexp    { return m.attrName }
func (m *Match) AttrNameNotRE() *regexp.Regexp { return m.attrNameNot }
func (m *Match) ValueRE() *regexp.Regexp       { return m.value }
func (m *Match) NameRE() *regexp.Regexp        { return m.name }

// ByID returns one rule by its declared id.
func (p *Pack) ByID(id string) (*Rule, bool) {
	r, ok := p.byID[id]
	return r, ok
}

// Group returns the ordered members of a named group.
func (p *Pack) Group(name string) []*Rule { return p.byGroup[name] }

// GroupNames lists every group in the order it first appears in the pack.
func (p *Pack) GroupNames() []string { return p.groups }

// Ungrouped returns the rules that belong to no group, in pack order.
func (p *Pack) Ungrouped() []*Rule {
	var out []*Rule
	for _, r := range p.Rules {
		if r.Group == "" {
			out = append(out, r)
		}
	}
	return out
}

// Categories lists every category the pack defines, in first-appearance
// order.
func (p *Pack) Categories() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range p.Rules {
		if !seen[r.Category] {
			seen[r.Category] = true
			out = append(out, r.Category)
		}
	}
	return out
}

// DocsFor returns the documentation for a category.
func (p *Pack) DocsFor(category string) (*CategoryDoc, bool) {
	d, ok := p.byCat[category]
	return d, ok
}

// DocumentedCategories lists the categories carrying documentation, in pack
// order — the order docs/rules.md is generated in.
func (p *Pack) DocumentedCategories() []*CategoryDoc { return p.Docs }

// RequireIDs asserts that every id the binary reaches for by name is
// present. The exported credential helpers read their patterns out of this
// pack rather than keeping a second copy in Go, so a renamed id would
// silently disable secret detection everywhere those helpers are used —
// including the .tfvars and terragrunt scanners.
func (p *Pack) RequireIDs(ids ...string) error {
	var missing []string
	for _, id := range ids {
		if _, ok := p.byID[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("rule pack is missing ids the scanner reads by name: %s", strings.Join(missing, ", "))
	}
	return nil
}
