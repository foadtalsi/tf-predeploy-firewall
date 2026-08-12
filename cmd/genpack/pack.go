package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"sort"
)

// PackFormatVersion is bumped when the on-disk pack layout changes in a way
// older scanners can't read. The loader refuses a pack whose format version
// it doesn't recognise rather than silently mis-reading it.
const PackFormatVersion = 1

// Pack is one rule pack: everything the rule engine knows about a provider's
// resource types. A pack is self-describing — a scanner loads base and
// extended packs through the same code path, the only difference being where
// the bytes came from.
type Pack struct {
	FormatVersion int `json:"format_version"`

	// ID identifies the pack ("aws-base", "aws-full"). Reported in scan
	// output so a finding can always be traced back to the pack that made it.
	ID string `json:"id"`

	// Provider is the Terraform provider these resources belong to.
	Provider string `json:"provider"`

	// ProviderVersion records which provider release the attribute surface
	// was generated from, so "is this attribute really unknown?" has an
	// auditable answer.
	ProviderVersion string `json:"provider_version"`

	// Resources maps resource_type -> everything known about it.
	Resources map[string]*PackResource `json:"resources"`
}

// PackResource is the complete per-resource-type knowledge base entry.
type PackResource struct {
	// TopLevel lists every argument name valid at the resource's top level,
	// including nested block names and Terraform meta-arguments.
	TopLevel []string `json:"top_level"`

	// NestedBlocks maps a dotted block path ("root_block_device",
	// "capacity_reservation_specification.capacity_reservation_target") to the
	// argument names valid inside it. Paths absent from this map are not
	// validated at all, so an uncurated block can never produce a finding.
	NestedBlocks map[string][]string `json:"nested_blocks,omitempty"`

	// ForceNewTopLevel lists top-level arguments whose modification forces
	// the resource to be destroyed and recreated.
	ForceNewTopLevel []string `json:"force_new_top_level,omitempty"`

	// ForceNewNested maps the same dotted block paths as NestedBlocks to the
	// ForceNew argument names inside them.
	ForceNewNested map[string][]string `json:"force_new_nested,omitempty"`

	// Critical marks a resource type as stateful enough that destroying it
	// loses data, so it is expected to carry lifecycle { prevent_destroy }.
	Critical bool `json:"critical,omitempty"`

	// Pricing is the coarse monthly cost estimate used by the plan-JSON cost
	// impact rule. Absent means "contributes $0", never "guess".
	Pricing *PackPricing `json:"pricing,omitempty"`
}

// PackPricing mirrors schema.PricingSpec on the wire.
type PackPricing struct {
	Base        float64            `json:"base,omitempty"`
	Attribute   string             `json:"attribute,omitempty"`
	ByAttribute map[string]float64 `json:"by_attribute,omitempty"`
	Default     float64            `json:"default,omitempty"`
}

// sortAll normalises every list in the pack so that regenerating from an
// unchanged provider produces a byte-identical file — otherwise every
// regeneration would show up as a diff and the packs couldn't be reviewed.
func (p *Pack) sortAll() {
	for _, r := range p.Resources {
		sort.Strings(r.TopLevel)
		sort.Strings(r.ForceNewTopLevel)
		for _, v := range r.NestedBlocks {
			sort.Strings(v)
		}
		for _, v := range r.ForceNewNested {
			sort.Strings(v)
		}
	}
}

// writeGzipJSON writes the pack as gzipped JSON. Packs are gzipped on disk
// because the full AWS pack is ~14 MB of JSON that compresses to ~0.6 MB —
// the difference between an embeddable file and one that isn't.
func (p *Pack) writeGzipJSON(path string) error {
	p.sortAll()

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Best compression: this runs once at generation time, but the result is
	// downloaded by every CI runner on every scan.
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(zw)
	if err := enc.Encode(p); err != nil {
		return fmt.Errorf("encoding pack: %w", err)
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return f.Close()
}

// subset returns a new pack containing only the named resource types — used
// to cut the free base pack out of the full generated one, so the two can
// never drift apart or disagree about the same resource.
func (p *Pack) subset(id string, types []string) *Pack {
	out := &Pack{
		FormatVersion:   p.FormatVersion,
		ID:              id,
		Provider:        p.Provider,
		ProviderVersion: p.ProviderVersion,
		Resources:       make(map[string]*PackResource, len(types)),
	}
	for _, t := range types {
		if r, ok := p.Resources[t]; ok {
			out.Resources[t] = r
		}
	}
	return out
}
