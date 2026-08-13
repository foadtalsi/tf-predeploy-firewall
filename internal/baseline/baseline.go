// Package baseline implements "accept everything that exists today, enforce
// from now on".
//
// This is the feature that decides whether the scanner can be adopted at all
// on a repository that already exists. Point it at a mature Terraform estate
// and it reports hundreds of findings — every one of them arguably true, and
// collectively useless, because the only available response is to lower
// block_threshold until the tool stops complaining, which is the same as
// uninstalling it.
//
// A baseline is a committed file recording what was already there. Those
// findings still appear in the PR comment, in their own section, but they
// don't block a merge. Anything new does. The debt stays visible and the
// bleeding stops, which is the only sequence that works on a codebase nobody
// has time to fix all at once.
//
// Matching is on category + resource + file, deliberately NOT on line number:
// a baseline that breaks when someone adds an unrelated line above would be
// worse than no baseline. It is the same key the control plane's per-finding
// waivers use, so "accepted" means one thing in this tool rather than two.
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

// FormatVersion guards against reading a baseline written by a future
// scanner whose semantics we don't know. Accepting one blindly could silence
// findings the author never agreed to.
const FormatVersion = 1

// Entry is one accepted finding.
type Entry struct {
	Category string `json:"category"`
	Resource string `json:"resource"`
	File     string `json:"file"`

	// Message and Line are recorded for the human reading the diff of this
	// file — they are never matched on. Messages get reworded as the scanner
	// improves, and lines move; matching on either would make every upgrade
	// resurrect the whole backlog.
	Message string `json:"message,omitempty"`
	Line    int    `json:"line,omitempty"`
}

func (e Entry) key() string {
	return e.Category + "\x00" + e.Resource + "\x00" + e.File
}

// File is the on-disk baseline.
type File struct {
	FormatVersion int     `json:"format_version"`
	GeneratedAt   string  `json:"generated_at,omitempty"`
	Note          string  `json:"_note,omitempty"`
	Entries       []Entry `json:"entries"`
}

// Baseline is a loaded baseline, ready to match findings against.
type Baseline struct {
	byKey map[string]Entry
	used  map[string]bool
}

// Load reads a baseline file. A missing file is not an error — it means
// "no baseline", which is the normal state for most repositories.
func Load(path string) (*Baseline, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading baseline %s: %w", path, err)
	}

	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}
	if f.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("baseline %s has format version %d, this scanner understands %d — regenerate it with --write-baseline",
			path, f.FormatVersion, FormatVersion)
	}

	b := &Baseline{byKey: make(map[string]Entry, len(f.Entries)), used: map[string]bool{}}
	for _, e := range f.Entries {
		b.byKey[e.key()] = e
	}
	return b, nil
}

// Apply marks every finding present in the baseline as accepted, and returns
// the findings with those marks set.
//
// It reuses the same "accepted but still shown" mechanism as waivers, so a
// baselined finding is excluded from the block decision and from SARIF, but
// never silently disappears from the report.
func (b *Baseline) Apply(findings []report.Finding) []report.Finding {
	if b == nil {
		return findings
	}
	for i, f := range findings {
		k := Entry{Category: string(f.Category), Resource: f.Resource, File: f.File}.key()
		if _, ok := b.byKey[k]; !ok {
			continue
		}
		b.used[k] = true
		findings[i].Waived = true
		findings[i].WaiverNote = "accepted in baseline"
	}
	return findings
}

// Stale returns the number of baseline entries that matched nothing in this
// scan — findings that have since been fixed, or resources that were removed.
//
// Reported rather than pruned automatically: silently dropping entries would
// let a baseline quietly re-accept a finding that comes back later. Cleaning
// up is a deliberate `--write-baseline`.
func (b *Baseline) Stale() int {
	if b == nil {
		return 0
	}
	return len(b.byKey) - len(b.used)
}

// Size returns how many findings the baseline accepts.
func (b *Baseline) Size() int {
	if b == nil {
		return 0
	}
	return len(b.byKey)
}

// Write records the given findings as the new baseline.
//
// Only genuinely reportable findings are recorded: writing a baseline from a
// scan that had waivers applied would bake those waivers into the file and
// make them permanent, outliving the dashboard decision that created them.
func Write(path string, findings []report.Finding, generatedAt string) error {
	seen := map[string]bool{}
	var entries []Entry

	for _, f := range findings {
		e := Entry{
			Category: string(f.Category),
			Resource: f.Resource,
			File:     f.File,
			Message:  f.Message,
			Line:     f.Line,
		}
		if seen[e.key()] {
			continue
		}
		seen[e.key()] = true
		entries = append(entries, e)
	}

	// Stable order so regenerating an unchanged repo produces no diff.
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].File != entries[j].File {
			return entries[i].File < entries[j].File
		}
		if entries[i].Resource != entries[j].Resource {
			return entries[i].Resource < entries[j].Resource
		}
		return entries[i].Category < entries[j].Category
	})

	doc := File{
		FormatVersion: FormatVersion,
		GeneratedAt:   generatedAt,
		Note: "Findings accepted as pre-existing. They stay visible in the PR comment " +
			"but do not block a merge; anything not listed here does. Matched on " +
			"category+resource+file, never on line number. Regenerate with --write-baseline.",
		Entries: entries,
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}
