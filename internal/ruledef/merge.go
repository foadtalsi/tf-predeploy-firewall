package ruledef

import (
	"fmt"
	"sort"
)

// MergeReport says what layering one pack over another actually did.
//
// It exists to be printed. A pack that overrides a rule the author did not
// mean to override, or adds one whose id they typo'd into something new,
// behaves perfectly and silently — the scan just runs different rules than
// they think. The counts are cheap to read on stderr and make that visible.
type MergeReport struct {
	Overridden []string
	Added      []string
	Disabled   []string
	Inherited  int
}

func (r MergeReport) String() string {
	s := fmt.Sprintf("%d inherited", r.Inherited)
	if len(r.Overridden) > 0 {
		s += fmt.Sprintf(", %d overridden (%s)", len(r.Overridden), join(r.Overridden))
	}
	if len(r.Added) > 0 {
		s += fmt.Sprintf(", %d added (%s)", len(r.Added), join(r.Added))
	}
	if len(r.Disabled) > 0 {
		s += fmt.Sprintf(", %d disabled (%s)", len(r.Disabled), join(r.Disabled))
	}
	return s
}

func join(ids []string) string {
	const max = 5
	if len(ids) <= max {
		return joinAll(ids)
	}
	return joinAll(ids[:max]) + fmt.Sprintf(" and %d more", len(ids)-max)
}

func joinAll(ids []string) string {
	out := ""
	for i, id := range ids {
		if i > 0 {
			out += ", "
		}
		out += id
	}
	return out
}

// Merge layers overlay on top of base and returns the combined pack.
//
// Rules are matched by id. An overlay rule whose id exists in base replaces
// it *in base's position*, so overriding one rule cannot reorder the others —
// and order carries meaning here, since a group's members are ordered
// alternatives. An overlay rule with a new id is appended.
//
// Neither input is modified: the built-in pack is a process-wide singleton,
// and a merge that mutated it would leave every later caller looking at
// somebody's overlay.
func Merge(base, overlay *Pack) (*Pack, *MergeReport, error) {
	if base == nil || overlay == nil {
		return nil, nil, fmt.Errorf("both packs are required")
	}

	report := &MergeReport{}
	byID := map[string]*Rule{}
	for _, r := range overlay.Rules {
		if _, dup := byID[r.ID]; dup {
			return nil, nil, fmt.Errorf("overlay declares id %q twice", r.ID)
		}
		byID[r.ID] = r
	}

	merged := &Pack{Version: base.Version}
	used := map[string]bool{}

	for _, r := range base.Rules {
		if override, ok := byID[r.ID]; ok {
			used[r.ID] = true
			if override.Disabled {
				report.Disabled = append(report.Disabled, r.ID)
				continue
			}
			report.Overridden = append(report.Overridden, r.ID)
			merged.Rules = append(merged.Rules, override)
			continue
		}
		report.Inherited++
		merged.Rules = append(merged.Rules, r)
	}

	for _, r := range overlay.Rules {
		if used[r.ID] {
			continue
		}
		if r.Disabled {
			// Disabling something that was never there is the signature of a
			// typo, and a typo here means the rule the author meant to switch
			// off is still running.
			return nil, nil, fmt.Errorf(
				"rule %q is marked disabled but no rule with that id exists to disable — check the spelling against --print-rules", r.ID)
		}
		report.Added = append(report.Added, r.ID)
		merged.Rules = append(merged.Rules, r)
	}

	// Docs merge by category on the same override-or-append terms, so a pack
	// that reworded a rule can reword its explanation too. A rule whose
	// documentation still describes the old behaviour is worse than none.
	docByCat := map[string]*CategoryDoc{}
	for _, d := range overlay.Docs {
		docByCat[d.Category] = d
	}
	usedDoc := map[string]bool{}
	for _, d := range base.Docs {
		if override, ok := docByCat[d.Category]; ok {
			usedDoc[d.Category] = true
			merged.Docs = append(merged.Docs, override)
			continue
		}
		merged.Docs = append(merged.Docs, d)
	}
	for _, d := range overlay.Docs {
		if !usedDoc[d.Category] {
			merged.Docs = append(merged.Docs, d)
		}
	}

	if len(merged.Rules) == 0 {
		return nil, nil, fmt.Errorf("the merged pack has no rules left — the overlay disabled every one")
	}

	// Revalidated from scratch rather than trusted: two individually valid
	// packs can merge into an invalid one, most obviously by overriding a
	// group member with a rule of a different scope.
	if err := merged.index(); err != nil {
		return nil, nil, fmt.Errorf("merging packs: %w", err)
	}

	sort.Strings(report.Overridden)
	sort.Strings(report.Added)
	sort.Strings(report.Disabled)
	return merged, report, nil
}
