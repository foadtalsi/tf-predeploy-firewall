package ruledef

import (
	"strings"
	"testing"
)

const baseYAML = `
version: 1
rules:
  - id: first
    category: alpha
    severity: low
    message: m
    match: {scope: attribute, literal: true}
  - id: grouped_a
    category: alpha
    severity: high
    group: g
    message: m
    match: {scope: attribute, literal: true, value_matches: 'a'}
  - id: grouped_b
    category: alpha
    severity: high
    group: g
    message: m
    match: {scope: attribute, literal: true, value_matches: 'b'}
  - id: last
    category: beta
    severity: medium
    engine: unknown_attribute
docs:
  - category: alpha
    title: Alpha
    full_description: d
    markdown: md
`

func mustLoad(t *testing.T, y string) *Pack {
	t.Helper()
	p, err := Load([]byte(y))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	return p
}

func ids(p *Pack) []string {
	out := make([]string, 0, len(p.Rules))
	for _, r := range p.Rules {
		out = append(out, r.ID)
	}
	return out
}

// Order carries meaning — a group's members are ordered alternatives — so an
// override has to land where the rule it replaces was, not at the end.
func TestMerge_OverrideKeepsPosition(t *testing.T) {
	base := mustLoad(t, baseYAML)
	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - id: grouped_a
    category: alpha
    severity: critical
    group: g
    message: reworded
    match: {scope: attribute, literal: true, value_matches: 'A'}
`)

	merged, report, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.Join(ids(merged), ","), "first,grouped_a,grouped_b,last"; got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
	if len(report.Overridden) != 1 || report.Overridden[0] != "grouped_a" {
		t.Errorf("report.Overridden = %v", report.Overridden)
	}
	if report.Inherited != 3 {
		t.Errorf("report.Inherited = %d, want 3", report.Inherited)
	}

	r, _ := merged.ByID("grouped_a")
	if r.Severity != "critical" || r.Message != "reworded" {
		t.Errorf("the override did not take: %+v", r)
	}
	// The group must still hold both members, in order.
	if got := len(merged.Group("g")); got != 2 {
		t.Errorf("group g has %d members, want 2", got)
	}
}

func TestMerge_AddsNewRules(t *testing.T) {
	base := mustLoad(t, baseYAML)
	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - id: ours
    category: org_policy
    severity: critical
    message: m
    match: {scope: attribute, literal: true, attr_names: [acl]}
`)
	merged, report, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if report.Added == nil || report.Added[0] != "ours" {
		t.Errorf("report.Added = %v", report.Added)
	}
	if got, want := strings.Join(ids(merged), ","), "first,grouped_a,grouped_b,last,ours"; got != want {
		t.Errorf("order = %s, want %s", got, want)
	}
	// Adding must never cost you the built-ins. That is the whole reason
	// extends exists rather than a second flag.
	if report.Inherited != 4 {
		t.Errorf("report.Inherited = %d, want all 4 kept", report.Inherited)
	}
}

// Turning off one detector must not take its category with it — that is what
// `ignore_rules:` already does, and why it is not enough.
func TestMerge_DisableRemovesOnlyThatRule(t *testing.T) {
	base := mustLoad(t, baseYAML)
	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - id: grouped_a
    disabled: true
`)
	merged, report, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	if _, still := merged.ByID("grouped_a"); still {
		t.Error("grouped_a survived being disabled")
	}
	if _, ok := merged.ByID("grouped_b"); !ok {
		t.Error("disabling one group member removed the other")
	}
	if _, ok := merged.ByID("first"); !ok {
		t.Error("disabling one rule removed another in the same category")
	}
	if len(report.Disabled) != 1 {
		t.Errorf("report.Disabled = %v", report.Disabled)
	}
}

// Disabling a name that does not exist is the signature of a typo, and the
// consequence of guessing is that the rule the author meant to switch off is
// still running.
func TestMerge_DisablingAnUnknownIDIsAnError(t *testing.T) {
	base := mustLoad(t, baseYAML)
	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - id: groupd_a
    disabled: true
`)
	_, _, err := Merge(base, overlay)
	if err == nil {
		t.Fatal("expected an error for the misspelled id")
	}
	if !strings.Contains(err.Error(), "groupd_a") {
		t.Errorf("error should quote the id, got %q", err)
	}
}

func TestMerge_RefusesToDisableEverything(t *testing.T) {
	base := mustLoad(t, baseYAML)
	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - {id: first, disabled: true}
  - {id: grouped_a, disabled: true}
  - {id: grouped_b, disabled: true}
  - {id: last, disabled: true}
`)
	if _, _, err := Merge(base, overlay); err == nil {
		t.Fatal("a pack that disables every rule must not silently scan nothing")
	}
}

// Two individually valid packs can merge into an invalid one. The merged
// result is revalidated rather than trusted.
func TestMerge_RevalidatesTheResult(t *testing.T) {
	base := mustLoad(t, baseYAML)
	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - id: grouped_a
    category: alpha
    severity: high
    group: g
    message: m
    match: {scope: block_attribute, literal: true, value_matches: 'a'}
`)
	_, _, err := Merge(base, overlay)
	if err == nil {
		t.Fatal("overriding a group member with a different scope must be rejected")
	}
	if !strings.Contains(err.Error(), "mixes scopes") {
		t.Errorf("error should explain the scope conflict, got %q", err)
	}
}

// The built-in pack is a process-wide singleton. A merge that mutated it
// would leave every later caller looking at somebody's overlay.
func TestMerge_DoesNotMutateItsInputs(t *testing.T) {
	base := mustLoad(t, baseYAML)
	before := strings.Join(ids(base), ",")
	original, _ := base.ByID("grouped_a")
	originalSeverity := original.Severity

	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - id: grouped_a
    category: alpha
    severity: critical
    group: g
    message: m
    match: {scope: attribute, literal: true, value_matches: 'A'}
  - id: extra
    category: alpha
    severity: low
    message: m
    match: {scope: attribute, literal: true}
`)
	if _, _, err := Merge(base, overlay); err != nil {
		t.Fatal(err)
	}

	if got := strings.Join(ids(base), ","); got != before {
		t.Errorf("base pack was mutated: %s", got)
	}
	if again, _ := base.ByID("grouped_a"); again.Severity != originalSeverity {
		t.Errorf("base rule was mutated: severity is now %q", again.Severity)
	}
}

func TestMerge_DocsOverrideByCategory(t *testing.T) {
	base := mustLoad(t, baseYAML)
	overlay := mustLoad(t, `
version: 1
extends: builtin
rules:
  - id: first
    category: alpha
    severity: low
    message: m
    match: {scope: attribute, literal: true}
docs:
  - category: alpha
    title: Alpha, our way
    full_description: d2
    markdown: md2
  - category: org_policy
    title: Our policy
    full_description: d3
    markdown: md3
`)
	merged, _, err := Merge(base, overlay)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := merged.DocsFor("alpha")
	if !ok || d.Title != "Alpha, our way" {
		t.Errorf("category docs were not overridden: %+v", d)
	}
	if _, ok := merged.DocsFor("org_policy"); !ok {
		t.Error("new category docs were not added")
	}
}

func TestLoad_RejectsUnknownExtends(t *testing.T) {
	_, err := Load([]byte("version: 1\nextends: everything\nrules:\n  - id: a\n    category: c\n    severity: low\n    engine: unknown_attribute\n"))
	if err == nil || !strings.Contains(err.Error(), "extends") {
		t.Fatalf("expected an extends error, got %v", err)
	}
}
