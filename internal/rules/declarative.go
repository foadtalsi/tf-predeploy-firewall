package rules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/ruledef"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// declarativeRule evaluates one or more rule definitions that examine the
// same kind of location.
//
// A group holds ordered alternatives and the first to match a location wins,
// which is what makes a JWT get reported as a JWT rather than as "a
// high-entropy string": the specific formats are listed before the
// statistical fallback, and the fallback never gets to speak about a value
// that already has a name. An ungrouped rule is a group of one, so there is
// only one code path.
type declarativeRule struct {
	specs []*ruledef.Rule
	scope string
}

// attrLocation is one place a value can sit: a resource's own attribute, or
// an attribute inside one of its nested blocks.
type attrLocation struct {
	name  string
	attr  *parser.Attribute
	block *parser.NestedBlock // nil for a top-level attribute
}

func (d declarativeRule) Check(in FileInput, kb *schema.KnowledgeBase) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		if d.scope == "resource_name" {
			if f, ok := d.checkResourceName(in, res); ok {
				findings = append(findings, f)
			}
			continue
		}
		for _, loc := range d.locations(res) {
			if f, ok := d.checkLocation(in, res, loc); ok {
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// locations enumerates the candidate attributes for this rule's scope.
//
// Sorted by name because Go map iteration is not ordered, and a scanner that
// reports the same file in a different order on every run is one nobody can
// diff two reports of.
func (d declarativeRule) locations(res *parser.Resource) []attrLocation {
	m := d.specs[0].Match
	var out []attrLocation

	if m.Scope == "attribute" || m.Scope == "any_attribute" {
		for _, name := range sortedKeys(res.Attributes) {
			out = append(out, attrLocation{name: name, attr: res.Attributes[name]})
		}
	}
	if m.Scope == "block_attribute" || m.Scope == "any_attribute" {
		for _, blk := range res.Blocks {
			if len(m.BlockTypes) > 0 && !contains(m.BlockTypes, blk.Type) {
				continue
			}
			for _, name := range sortedKeys(blk.Attributes) {
				out = append(out, attrLocation{name: name, attr: blk.Attributes[name], block: blk})
			}
		}
	}
	return out
}

// checkLocation runs the group's alternatives against one attribute and
// returns the first finding produced.
func (d declarativeRule) checkLocation(in FileInput, res *parser.Resource, loc attrLocation) (report.Finding, bool) {
	for _, spec := range d.specs {
		if !matchesResource(spec.Match, res) {
			continue
		}
		bits, ok := matchesAttr(spec.Match, loc.name, loc.attr)
		if !ok {
			continue
		}
		return d.finding(in, spec, res, loc, bits), true
	}
	return report.Finding{}, false
}

func (d declarativeRule) checkResourceName(in FileInput, res *parser.Resource) (report.Finding, bool) {
	for _, spec := range d.specs {
		if !matchesResource(spec.Match, res) {
			continue
		}
		if re := spec.Match.NameRE(); re == nil || !re.MatchString(res.Name) {
			continue
		}
		vars := baseVars(res)
		return report.Finding{
			File:     in.Path,
			Line:     res.DefRange.Start.Line,
			Category: report.Category(spec.Category),
			Severity: report.Severity(spec.Severity),
			Resource: res.Address(),
			Message:  expand(spec.Message, vars),
		}, true
	}
	return report.Finding{}, false
}

func (d declarativeRule) finding(in FileInput, spec *ruledef.Rule, res *parser.Resource, loc attrLocation, bits float64) report.Finding {
	vars := baseVars(res)
	vars["attr"] = loc.name
	vars["attr_q"] = strconv.Quote(loc.name)
	vars["value"] = loc.attr.RawValue
	vars["value_q"] = strconv.Quote(loc.attr.RawValue)
	vars["length"] = strconv.Itoa(len(loc.attr.RawValue))
	vars["label"] = spec.Label
	vars["via"] = viaSuffix(loc.attr)
	vars["bits"] = fmt.Sprintf("%.1f", bits)

	blockType := ""
	if loc.block != nil {
		blockType = loc.block.Type
		vars["block"] = blockType
		vars["location"] = fmt.Sprintf("(inside %s block) ", blockType)
	} else {
		vars["location"] = ""
	}
	vars["var"] = credentialVarName(res, blockType, loc.name)

	return report.Finding{
		File:       in.Path,
		Line:       loc.attr.Range.Start.Line,
		Category:   report.Category(spec.Category),
		Severity:   report.Severity(spec.Severity),
		Resource:   res.Address(),
		Message:    expand(spec.Message, vars),
		Suggestion: expand(spec.Suggestion, vars),
		Fix:        buildFix(spec, in.HeadSource, loc, vars),
	}
}

// buildFix renders a declarative fix, or returns nil when it cannot be
// produced exactly. Every path out of here that is not a complete, verbatim
// replacement returns nil: missing a one-click fix costs a click, and getting
// one wrong commits broken HCL to someone's branch.
func buildFix(spec *ruledef.Rule, src []byte, loc attrLocation, vars map[string]string) *report.Fix {
	if spec.Fix == nil {
		return nil
	}
	// The literal was reached through a variable or a local, so the line under
	// this finding already reads `password = var.db_password` and is correct.
	// Rewriting it to point at a different variable would fix nothing while
	// looking like it had — the value lives in the declaration elsewhere.
	if spec.Fix.SkipWhenResolved && loc.attr.ResolvedFrom != "" {
		return nil
	}

	lines := expandAll(spec.Fix.Lines, vars)
	start, end, out, ok := replaceAttrLine(src, loc.attr.Range, loc.name, lines[0])
	if !ok {
		return nil
	}
	return &report.Fix{
		StartLine: start,
		EndLine:   end,
		Lines:     out,
		Note:      expand(spec.Fix.Note, vars),
	}
}

func baseVars(res *parser.Resource) map[string]string {
	return map[string]string{
		"resource": res.Address(),
		"type":     res.Type,
		"name":     res.Name,
		"name_q":   strconv.Quote(res.Name),
	}
}

// matchesResource applies the block-level filters. Empty filters match
// everything, so a rule says only what it actually restricts.
func matchesResource(m *ruledef.Match, res *parser.Resource) bool {
	if len(m.Kinds) > 0 && !contains(m.Kinds, string(res.Kind)) {
		return false
	}
	if len(m.ResourceTypes) > 0 && !contains(m.ResourceTypes, res.Type) {
		return false
	}
	return true
}

// matchesAttr applies every value-level condition, returning the measurement
// a predicate produced so the message can quote it.
func matchesAttr(m *ruledef.Match, name string, attr *parser.Attribute) (float64, bool) {
	if m.Literal != nil && *m.Literal != attr.IsLiteral {
		return 0, false
	}
	if m.MinLength > 0 && len(attr.RawValue) < m.MinLength {
		return 0, false
	}

	if len(m.AttrNames) > 0 && !contains(m.AttrNames, name) {
		return 0, false
	}
	if re := m.AttrNameRE(); re != nil && !re.MatchString(name) {
		return 0, false
	}
	if re := m.AttrNameNotRE(); re != nil && re.MatchString(name) {
		return 0, false
	}
	if m.AttrNameContains != "" &&
		!strings.Contains(strings.ToLower(name), strings.ToLower(m.AttrNameContains)) {
		return 0, false
	}

	if len(m.ValueNotOneOf) > 0 && contains(m.ValueNotOneOf, attr.RawValue) {
		return 0, false
	}
	if m.ValueContains != "" && !strings.Contains(attr.RawValue, m.ValueContains) {
		return 0, false
	}
	if re := m.ValueRE(); re != nil {
		match := re.FindString(attr.RawValue)
		if match == "" {
			return 0, false
		}
		// The confirmation judges the substring the regex found, not the
		// whole value: a secret inside a longer string must still be caught,
		// and a long benign string must not be rescued by its benign parts.
		if m.Confirm != "" && !confirmPredicates[m.Confirm](match) {
			return 0, false
		}
	}
	if m.Predicate != "" {
		bits, ok := valuePredicates[m.Predicate](attr.RawValue)
		if !ok {
			return 0, false
		}
		return bits, true
	}

	return 0, true
}

func sortedKeys(m map[string]*parser.Attribute) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
