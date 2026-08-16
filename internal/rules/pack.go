package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/ruledef"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// Wiring between the rule pack and this engine: turning definitions into
// runnable rules, and answering the questions other packages ask about the
// pack's patterns without keeping a second copy of them in Go.

// requiredIDs are the rules this binary reaches for by name. The .tfvars and
// terragrunt scanners judge a value by exactly the same standard as a
// resource attribute, and they do it by reading these definitions rather
// than by re-declaring the patterns — two divergent definitions of "looks
// like a secret" would be a bug waiting to happen.
var requiredIDs = []string{"hardcoded_credential", "open_cidr"}

const credentialValueGroup = "credential_value"

type packRefs struct {
	pack             *ruledef.Pack
	credentialName   *regexp.Regexp
	credentialValues []*ruledef.Rule
	openCIDR         string
}

var loadBuiltin = sync.OnceValue(func() *packRefs {
	pack, err := ruledef.Builtin()
	if err == nil {
		err = pack.RequireIDs(requiredIDs...)
	}
	if err == nil {
		err = validatePredicates(pack)
	}
	if err == nil && len(pack.Group(credentialValueGroup)) == 0 {
		err = fmt.Errorf("rule pack defines no %q group", credentialValueGroup)
	}
	if err != nil {
		// The pack is embedded in this binary, so a failure here is a broken
		// build rather than a bad input, and it is not survivable: every path
		// that could "carry on without it" ends with the scanner reporting a
		// clean run over Terraform it never actually inspected. A scanner that
		// finds nothing because it is broken must not be mistaken for one that
		// found nothing because there was nothing to find.
		panic("tf-predeploy-firewall: " + err.Error())
	}

	credential, _ := pack.ByID("hardcoded_credential")
	openCIDR, _ := pack.ByID("open_cidr")

	var values []*ruledef.Rule
	for _, r := range pack.Group(credentialValueGroup) {
		if r.Match.ValueRE() != nil {
			values = append(values, r)
		}
	}

	return &packRefs{
		pack:             pack,
		credentialName:   credential.Match.AttrNameRE(),
		credentialValues: values,
		openCIDR:         openCIDR.Match.ValueContains,
	}
})

// BuiltinPack returns the rule pack compiled into this binary.
func BuiltinPack() *ruledef.Pack { return loadBuiltin().pack }

// validatePredicates rejects a pack naming a predicate this binary does not
// implement. Skipping the unknown name instead would leave the rule loaded,
// matching nothing, and reporting success — the failure mode this whole
// format exists to avoid.
func validatePredicates(p *ruledef.Pack) error {
	confirm, value := knownPredicates()
	sort.Strings(confirm)
	sort.Strings(value)

	for _, r := range p.Rules {
		if r.Match == nil {
			continue
		}
		if n := r.Match.Confirm; n != "" && confirmPredicates[n] == nil {
			return fmt.Errorf("rule %q names unknown confirm predicate %q (available: %s)",
				r.ID, n, strings.Join(confirm, ", "))
		}
		if n := r.Match.Predicate; n != "" && valuePredicates[n] == nil {
			return fmt.Errorf("rule %q names unknown predicate %q (available: %s)",
				r.ID, n, strings.Join(value, ", "))
		}
	}
	return nil
}

// Options carries the settings a compiled engine takes from configuration
// rather than from the pack, because they are per-repository choices.
type Options struct {
	// CostThresholdUSD is the estimated monthly increase that makes a cost
	// finding. Zero leaves the static cost rule out of the set entirely.
	CostThresholdUSD float64
}

// FromPack builds the runnable rule set for a pack.
//
// Declarative rules are grouped first, so that ordered alternatives are
// evaluated by a single rule and first-match-wins actually means something;
// engine rules resolve to their compiled implementation. Order follows the
// pack, which is why the pack reads top to bottom in the order a reader
// would want the rules explained.
func FromPack(p *ruledef.Pack, opts Options) ([]Rule, error) {
	built, err := buildRules(p, opts)
	if err != nil {
		return nil, err
	}
	out := make([]Rule, 0, len(built))
	for _, b := range built {
		out = append(out, b.rule)
	}
	return out, nil
}

// builtRule keeps a runnable rule next to the declaration it came from, so
// callers can filter by what the pack says about it without inspecting Go
// types.
type builtRule struct {
	rule Rule
	spec *ruledef.Rule // the definition, or a group's first member
}

func buildRules(p *ruledef.Pack, opts Options) ([]builtRule, error) {
	var out []builtRule
	emitted := map[string]bool{}

	for _, spec := range p.Rules {
		switch {
		case spec.Group != "":
			if emitted[spec.Group] {
				continue // the whole group was emitted with its first member
			}
			emitted[spec.Group] = true
			group := p.Group(spec.Group)
			out = append(out, builtRule{
				rule: declarativeRule{specs: group, scope: group[0].Match.Scope},
				spec: group[0],
			})

		case spec.Match != nil:
			out = append(out, builtRule{
				rule: declarativeRule{specs: []*ruledef.Rule{spec}, scope: spec.Match.Scope},
				spec: spec,
			})

		default:
			rule, ok, err := compiledEngine(spec, opts)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, builtRule{rule: rule, spec: spec})
			}
		}
	}
	return out, nil
}

// ruleSet runs several rules as one, so a caller can treat "everything the
// pack says about credentials" as a single detector.
type ruleSet []Rule

func (rs ruleSet) Check(in FileInput, kb *schema.KnowledgeBase) []report.Finding {
	var findings []report.Finding
	for _, r := range rs {
		findings = append(findings, r.Check(in, kb)...)
	}
	return findings
}

// RulesForCategory returns everything a pack defines for one category as a
// single rule. Used to run or reason about one category on its own —
// reporting what a category would find, and testing a category's detectors
// together rather than one declaration at a time.
//
// Built through the same path as a full scan, so that grouping — and with it
// first-match-wins — behaves identically. A category evaluated by its own
// code path would make every test of it a test of something else.
func RulesForCategory(p *ruledef.Pack, category string, opts Options) (Rule, error) {
	built, err := buildRules(p, opts)
	if err != nil {
		return nil, err
	}
	var out ruleSet
	for _, b := range built {
		if b.spec.Category == category {
			out = append(out, b.rule)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("pack defines no runnable rules for category %q", category)
	}
	return out, nil
}

// compiledEngine resolves an `engine:` rule to its implementation. ok is
// false for engines that are not part of a static scan — the plan-based
// rules run from their own entry point, against terraform's JSON rather than
// against source, and are declared in the pack so that they are documented
// and configurable in the same place as everything else.
func compiledEngine(spec *ruledef.Rule, opts Options) (Rule, bool, error) {
	switch spec.Engine {
	case "unknown_attribute":
		return UnknownAttributeRule{}, true, nil
	case "force_new_change":
		return ForceNewChangeRule{}, true, nil
	case "missing_lifecycle":
		return MissingLifecycleRule{}, true, nil
	case "unpinned_version":
		return UnpinnedVersionRule{}, true, nil
	case "iam_wildcard":
		return IAMWildcardRule{}, true, nil

	case "static_cost":
		threshold := opts.CostThresholdUSD
		if threshold == 0 {
			if v, ok := spec.Params["threshold_usd"]; ok {
				parsed, err := strconv.ParseFloat(v, 64)
				if err != nil {
					return nil, false, fmt.Errorf("rule %q: threshold_usd %q is not a number: %w", spec.ID, v, err)
				}
				threshold = parsed
			}
		}
		if threshold <= 0 {
			return nil, false, nil
		}
		return StaticCostRule{ThresholdUSD: threshold}, true, nil

	case "confirmed_replace", "unexpected_drift", "large_blast_radius", "plan_cost_impact":
		return nil, false, nil

	default:
		return nil, false, fmt.Errorf("rule %q names unknown engine %q", spec.ID, spec.Engine)
	}
}

// IsCredentialAttrName reports whether name looks like a credential-bearing
// attribute by name alone (password, api_key, token, …).
//
// Exported alongside MatchCredentialValuePattern, IsOpenCIDR and
// LooksLikeSecret so the non-resource scanners (internal/tfvars,
// internal/terragrunt) apply the same standard to terragrunt.hcl's inputs
// and to .tfvars files, neither of which goes through parser.Resource. All
// four read the built-in pack, so there is exactly one definition of each.
func IsCredentialAttrName(name string) bool {
	re := loadBuiltin().credentialName
	return re != nil && re.MatchString(name)
}

// MatchCredentialValuePattern checks value against the well-known credential
// formats the pack declares, regardless of which attribute it came from.
// Returns the matched pattern's human-readable label and true, or ("", false).
func MatchCredentialValuePattern(value string) (label string, ok bool) {
	for _, spec := range loadBuiltin().credentialValues {
		m := spec.Match
		if m.MinLength > 0 && len(value) < m.MinLength {
			continue
		}
		match := m.ValueRE().FindString(value)
		if match == "" {
			continue
		}
		if m.Confirm != "" && !confirmPredicates[m.Confirm](match) {
			continue
		}
		return spec.Label, true
	}
	return "", false
}

// IsOpenCIDR reports whether value is the wide-open CIDR block the pack's
// open_cidr rule looks for.
func IsOpenCIDR(value string) bool {
	return value == loadBuiltin().openCIDR
}
