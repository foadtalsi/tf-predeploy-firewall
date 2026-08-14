package ruledef

import (
	"strings"
	"testing"
)

func TestBuiltin_LoadsAndValidates(t *testing.T) {
	p, err := Builtin()
	if err != nil {
		t.Fatalf("the embedded rule pack must always load: %v", err)
	}
	if len(p.Rules) == 0 {
		t.Fatal("no rules")
	}
	if err := p.RequireIDs("hardcoded_credential", "open_cidr"); err != nil {
		t.Error(err)
	}
}

// Every category a rule reports has to have somewhere for the reader to go.
func TestBuiltin_EveryCategoryIsDocumented(t *testing.T) {
	p, _ := Builtin()
	for _, c := range p.Categories() {
		d, ok := p.DocsFor(c)
		if !ok {
			t.Errorf("category %q has rules but no docs entry", c)
			continue
		}
		if d.Title == "" || d.FullDescription == "" || d.Markdown == "" {
			t.Errorf("category %q has an incomplete docs entry", c)
		}
	}
}

// The group's whole purpose is precedence: the specific credential formats
// must be tried before the statistical fallback, or every JWT gets reported
// as "a high-entropy string".
func TestBuiltin_EntropyFallbackIsLastInItsGroup(t *testing.T) {
	p, _ := Builtin()
	group := p.Group("credential_value")
	if len(group) < 2 {
		t.Fatalf("expected an ordered credential_value group, got %d rules", len(group))
	}
	for i, r := range group {
		isFallback := r.Match.Predicate != "" && r.Match.ValueMatches == ""
		if isFallback && i != len(group)-1 {
			t.Errorf("rule %q is a catch-all but sits at position %d of %d — every more specific format after it is unreachable",
				r.ID, i+1, len(group))
		}
	}
}

func load(t *testing.T, yaml string) error {
	t.Helper()
	_, err := Load([]byte(yaml))
	return err
}

// Every one of these is a mistake that would otherwise produce a rule that
// loads fine and matches nothing — a scanner reporting a clean run over
// Terraform it never really inspected.
func TestLoad_RejectsMistakesLoudly(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "no version",
			yaml: "rules:\n  - id: a\n    category: c\n    severity: low\n    engine: unknown_attribute\n",
			want: "no version",
		},
		{
			name: "version from a newer binary",
			yaml: "version: 99\nrules:\n  - id: a\n    category: c\n    severity: low\n    engine: unknown_attribute\n",
			want: "format version 99",
		},
		{
			name: "no rules at all",
			yaml: "version: 1\nrules: []\n",
			want: "declares no rules",
		},
		{
			name: "misspelled severity",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: sever\n    engine: unknown_attribute\n",
			want: "severity must be one of",
		},
		{
			name: "duplicate id",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    engine: unknown_attribute\n  - id: a\n    category: c\n    severity: low\n    engine: unknown_attribute\n",
			want: "duplicate id",
		},
		{
			name: "neither engine nor match",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n",
			want: "either an engine or a match",
		},
		{
			name: "unparseable regex",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    message: m\n    match:\n      scope: attribute\n      attr_name_matches: '([unclosed'\n",
			want: "attr_name_matches",
		},
		{
			// A match block with no conditions is not "match everything by
			// choice" — nobody writes that on purpose, and it would flag every
			// attribute in the repository.
			name: "match with no conditions",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    message: m\n    match:\n      scope: attribute\n",
			want: "at least one condition",
		},
		{
			name: "confirm without anything to confirm",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    message: m\n    match:\n      scope: attribute\n      literal: true\n      confirm: base64_secret\n",
			want: "value_matches is required",
		},
		{
			// First-match-wins is only meaningful between rules looking at the
			// same place; otherwise which one "wins" depends on traversal order.
			name: "group mixing scopes",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    group: g\n    message: m\n    match:\n      scope: attribute\n      literal: true\n  - id: b\n    category: c\n    severity: low\n    group: g\n    message: m\n    match:\n      scope: block_attribute\n      literal: true\n",
			want: "mixes scopes",
		},
		{
			name: "unsupported fix action",
			yaml: "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    message: m\n    match:\n      scope: attribute\n      literal: true\n    fix:\n      action: rewrite_everything\n      lines: ['x']\n",
			want: "fix action must be",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := load(t, tc.yaml)
			if err == nil {
				t.Fatalf("expected a load error mentioning %q, got none — this pack would run and quietly find nothing", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// A pack written for a future binary is refused outright rather than
// partly interpreted, because the half it cannot read is invisible.
func TestLoad_AcceptsCurrentVersion(t *testing.T) {
	if err := load(t, "version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    engine: unknown_attribute\n"); err != nil {
		t.Fatal(err)
	}
}

func TestRequireIDs_NamesWhatIsMissing(t *testing.T) {
	p, err := Load([]byte("version: 1\nrules:\n  - id: a\n    category: c\n    severity: low\n    engine: unknown_attribute\n"))
	if err != nil {
		t.Fatal(err)
	}
	err = p.RequireIDs("a", "b", "c")
	if err == nil {
		t.Fatal("expected an error for the missing ids")
	}
	if !strings.Contains(err.Error(), "b") || !strings.Contains(err.Error(), "c") {
		t.Errorf("error should name both missing ids, got %q", err)
	}
	if strings.Contains(err.Error(), " a,") {
		t.Errorf("error should not name the id that is present, got %q", err)
	}
}
