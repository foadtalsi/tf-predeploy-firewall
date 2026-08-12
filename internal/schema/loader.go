// Package schema holds what the rule engine knows about a Terraform
// provider's resource types — the valid argument surface, which arguments
// force a destroy+recreate, which types are stateful enough to guard, and a
// coarse price per type — without needing a plan, state, or credentials.
//
// All of it lives in *rule packs*: self-describing, generated data files
// (see cmd/genpack). The scanner embeds a free base pack covering the
// resource types most repos are made of, and can overlay a larger pack
// fetched at scan time. Both are generated from the same provider release by
// the same tool, so an overlaid pack never contradicts the base one — it
// only covers more types.
//
// Nothing here is hand-written per resource type any more. That matters:
// the curated lists this replaced claimed aws_instance had 29 arguments when
// the provider declares 71, and every missing argument was a false
// "hallucinated attribute" finding — at severity high, which blocks a PR.
package schema

import (
	"compress/gzip"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

//go:embed data/pack_aws_base.json.gz
var dataFS embed.FS

const basePackPath = "data/pack_aws_base.json.gz"

// PackFormatVersion is the on-disk pack layout this build understands. A pack
// declaring a newer version is rejected rather than half-read: a pack is
// security-relevant data, and silently ignoring fields we don't recognise
// could turn a blocking finding into a missed one.
const PackFormatVersion = 1

// ForceNewSpec describes which arguments (top-level and/or nested-block)
// trigger a destroy+recreate for a resource type.
type ForceNewSpec struct {
	// TopLevel lists top-level argument names that are ForceNew.
	TopLevel []string
	// NestedBlocks maps block path -> ForceNew argument names inside it.
	NestedBlocks map[string][]string
}

// ResourceSchema describes the valid arguments for a resource type, at both
// the top level and inside nested blocks.
type ResourceSchema struct {
	// TopLevel lists valid top-level argument names, including nested block
	// names and Terraform's own meta-arguments.
	TopLevel []string
	// NestedBlocks maps block path -> valid argument names inside it. Paths
	// absent from this map are not validated, so an unrecognised block can
	// never produce a finding.
	NestedBlocks map[string][]string
}

// PricingSpec is the curated approximate monthly cost for a resource type.
// A type may have a flat Base cost, and/or a cost that depends on the value
// of a single pricing-driving Attribute (e.g. instance_type). ByAttribute
// misses fall back to Default. All figures are coarse USD/month estimates.
type PricingSpec struct {
	// Tags are explicit: Go's case-insensitive field matching does not bridge
	// by_attribute -> ByAttribute, and a silently-nil price table degrades to
	// the flat default instead of failing.
	Base        float64            `json:"base"`         // flat monthly cost regardless of arguments
	Attribute   string             `json:"attribute"`    // argument whose value drives cost, if any
	ByAttribute map[string]float64 `json:"by_attribute"` // argument value -> monthly cost
	Default     float64            `json:"default"`      // used when Attribute is set but the value isn't in ByAttribute
}

// MonthlyCost returns the estimated monthly USD cost for a resource of this
// type, given its argument values (as strings). Base and attribute-driven
// costs add together, so a resource with both a flat base and a per-size
// price is handled.
func (p *PricingSpec) MonthlyCost(attrValue string) float64 {
	cost := p.Base
	if p.Attribute != "" {
		if v, ok := p.ByAttribute[attrValue]; ok {
			cost += v
		} else {
			cost += p.Default
		}
	}
	return cost
}

// packResource is one resource type's entry as it appears on disk. It is
// decoded lazily: the full AWS pack is ~14 MB of JSON covering ~1700 types,
// and a scan typically touches a few dozen. Holding the raw bytes and
// decoding on demand keeps the cost proportional to the repo being scanned
// rather than to the size of the pack.
type packResource struct {
	TopLevel         []string            `json:"top_level"`
	NestedBlocks     map[string][]string `json:"nested_blocks"`
	ForceNewTopLevel []string            `json:"force_new_top_level"`
	ForceNewNested   map[string][]string `json:"force_new_nested"`
	Critical         bool                `json:"critical"`
	Pricing          *PricingSpec        `json:"pricing"`
}

// loadedPack is a parsed pack: metadata plus still-encoded resource entries.
type loadedPack struct {
	FormatVersion   int                        `json:"format_version"`
	ID              string                     `json:"id"`
	Provider        string                     `json:"provider"`
	ProviderVersion string                     `json:"provider_version"`
	Resources       map[string]json.RawMessage `json:"resources"`

	decoded map[string]*packResource
}

func (p *loadedPack) resource(rType string) (*packResource, bool) {
	if p.decoded == nil {
		p.decoded = map[string]*packResource{}
	}
	if r, ok := p.decoded[rType]; ok {
		return r, r != nil
	}
	raw, ok := p.Resources[rType]
	if !ok {
		return nil, false
	}
	var r packResource
	if err := json.Unmarshal(raw, &r); err != nil {
		// A malformed entry means this type is simply unknown to us. It must
		// not take down a scan that has nothing to do with it.
		p.decoded[rType] = nil
		return nil, false
	}
	p.decoded[rType] = &r
	return &r, true
}

// AWS holds the loaded knowledge base. Construct with Load or LoadWith.
type AWS struct {
	// packs are consulted last-first, so a pack overlaid at scan time takes
	// precedence over the embedded base pack for any type they share.
	packs []*loadedPack
}

// Load returns the knowledge base built from the embedded base pack alone —
// the free tier, and the fallback whenever no extended pack is available.
func Load() (*AWS, error) {
	raw, err := dataFS.Open(basePackPath)
	if err != nil {
		return nil, fmt.Errorf("opening embedded base pack: %w", err)
	}
	defer raw.Close()

	base, err := parsePack(raw)
	if err != nil {
		return nil, fmt.Errorf("loading embedded base pack: %w", err)
	}
	return &AWS{packs: []*loadedPack{base}}, nil
}

// LoadWith returns the knowledge base with additional packs overlaid on top
// of the embedded base pack, in the order given. A pack that fails to parse
// is reported but does not prevent loading: losing an extended pack should
// degrade coverage, never break a customer's CI.
func LoadWith(extra ...io.Reader) (*AWS, []error) {
	var errs []error

	aws, err := Load()
	if err != nil {
		return nil, []error{err}
	}
	for _, r := range extra {
		p, err := parsePack(r)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		aws.packs = append(aws.packs, p)
	}
	return aws, errs
}

// parsePack reads a gzipped pack from r.
func parsePack(r io.Reader) (*loadedPack, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("pack is not gzip: %w", err)
	}
	defer zr.Close()

	var p loadedPack
	if err := json.NewDecoder(zr).Decode(&p); err != nil {
		return nil, fmt.Errorf("decoding pack: %w", err)
	}
	if p.FormatVersion != PackFormatVersion {
		return nil, fmt.Errorf("pack %q has format version %d, this build understands %d — upgrade the scanner",
			p.ID, p.FormatVersion, PackFormatVersion)
	}
	p.decoded = map[string]*packResource{}
	return &p, nil
}

// lookup finds a resource type in the most recently overlaid pack that has it.
func (a *AWS) lookup(rType string) (*packResource, bool) {
	for i := len(a.packs) - 1; i >= 0; i-- {
		if r, ok := a.packs[i].resource(rType); ok {
			return r, true
		}
	}
	return nil, false
}

// ResourceSchema returns the valid argument surface for a resource type.
// Types not covered by any loaded pack return false, and the unknown-argument
// rule skips them entirely — under-detecting is always preferable to flagging
// valid Terraform.
func (a *AWS) ResourceSchema(rType string) (*ResourceSchema, bool) {
	r, ok := a.lookup(rType)
	if !ok || len(r.TopLevel) == 0 {
		return nil, false
	}
	return &ResourceSchema{TopLevel: r.TopLevel, NestedBlocks: r.NestedBlocks}, true
}

// ForceNew returns the ForceNew arguments for a resource type.
func (a *AWS) ForceNew(rType string) (*ForceNewSpec, bool) {
	r, ok := a.lookup(rType)
	if !ok || (len(r.ForceNewTopLevel) == 0 && len(r.ForceNewNested) == 0) {
		return nil, false
	}
	return &ForceNewSpec{TopLevel: r.ForceNewTopLevel, NestedBlocks: r.ForceNewNested}, true
}

// IsCritical reports whether destroying this resource type loses data, and so
// whether it is expected to carry lifecycle { prevent_destroy = true }.
func (a *AWS) IsCritical(rType string) bool {
	r, ok := a.lookup(rType)
	return ok && r.Critical
}

// PricingFor returns the coarse monthly cost spec for a resource type.
// Types without one contribute $0 to a cost estimate rather than a guess.
func (a *AWS) PricingFor(rType string) (*PricingSpec, bool) {
	r, ok := a.lookup(rType)
	if !ok || r.Pricing == nil {
		return nil, false
	}
	return r.Pricing, true
}

// Coverage describes what the loaded packs know, for the scan header and for
// support questions of the form "why didn't it catch this?".
type Coverage struct {
	// Packs lists the loaded pack IDs, base first.
	Packs []string
	// ProviderVersion is the provider release the outermost pack describes.
	ProviderVersion string
	// ResourceTypes is the number of distinct types across all loaded packs.
	ResourceTypes int
	// Extended reports whether anything is overlaid on the base pack.
	Extended bool
}

// Coverage summarises the loaded packs.
func (a *AWS) Coverage() Coverage {
	seen := map[string]bool{}
	c := Coverage{Extended: len(a.packs) > 1}
	for _, p := range a.packs {
		c.Packs = append(c.Packs, p.ID)
		c.ProviderVersion = p.ProviderVersion
		for t := range p.Resources {
			seen[t] = true
		}
	}
	c.ResourceTypes = len(seen)
	sort.Strings(c.Packs)
	return c
}
