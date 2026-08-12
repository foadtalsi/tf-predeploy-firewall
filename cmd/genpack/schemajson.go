package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// This file turns `terraform providers schema -json` output into the
// attribute surface half of a pack.
//
// Why generate rather than curate: the hand-written schema this replaces
// listed 29 arguments for aws_instance; the provider actually declares 47
// plus 16 nested block types. Every argument missing from a curated list is
// a false "hallucinated attribute" finding on valid Terraform — and since
// that rule is severity high, a false positive there blocks a PR. Curation
// cannot keep up with a provider that ships every week, so it shouldn't try.

// tfProvidersSchema is the top level of `terraform providers schema -json`.
type tfProvidersSchema struct {
	FormatVersion   string                     `json:"format_version"`
	ProviderSchemas map[string]*tfProviderItem `json:"provider_schemas"`
}

type tfProviderItem struct {
	ResourceSchemas map[string]*tfResourceSchema `json:"resource_schemas"`
}

type tfResourceSchema struct {
	Version int      `json:"version"`
	Block   *tfBlock `json:"block"`
}

type tfBlock struct {
	Attributes map[string]*tfAttribute `json:"attributes"`
	BlockTypes map[string]*tfBlockType `json:"block_types"`
}

type tfAttribute struct {
	Required bool `json:"required"`
	Optional bool `json:"optional"`
	Computed bool `json:"computed"`
}

type tfBlockType struct {
	NestingMode string   `json:"nesting_mode"`
	Block       *tfBlock `json:"block"`
}

// metaArguments are valid inside any resource block but are Terraform's own,
// so they never appear in a provider's schema. Without them every `count`,
// `for_each` or `lifecycle` in a scanned repo would read as a hallucination.
var metaArguments = []string{
	"count",
	"depends_on",
	"for_each",
	"lifecycle",
	"provider",
	"provisioner",
	"connection",
	"dynamic",
}

// loadProviderSchema reads the terraform-generated schema JSON and returns
// the attribute surface per resource type, keyed the same way a Pack is.
func loadProviderSchema(path, providerAddr string) (map[string]*PackResource, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading provider schema: %w", err)
	}

	var doc tfProvidersSchema
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing provider schema JSON: %w", err)
	}

	item := doc.ProviderSchemas[providerAddr]
	if item == nil {
		available := make([]string, 0, len(doc.ProviderSchemas))
		for k := range doc.ProviderSchemas {
			available = append(available, k)
		}
		sort.Strings(available)
		return nil, fmt.Errorf("provider %q not in schema (found: %s)", providerAddr, strings.Join(available, ", "))
	}

	out := make(map[string]*PackResource, len(item.ResourceSchemas))
	for rType, rSchema := range item.ResourceSchemas {
		if rSchema.Block == nil {
			continue
		}
		res := &PackResource{NestedBlocks: map[string][]string{}}
		collectBlock(rSchema.Block, "", res)

		// Meta-arguments only apply at the resource's top level.
		res.TopLevel = append(res.TopLevel, metaArguments...)
		res.TopLevel = dedupe(res.TopLevel)

		if len(res.NestedBlocks) == 0 {
			res.NestedBlocks = nil
		}
		out[rType] = res
	}
	return out, nil
}

// collectBlock walks a block and its nested blocks recursively, recording the
// valid argument names at each dotted path.
//
// A nested block's own name counts as a valid argument of its parent: HCL
// allows both `root_block_device { ... }` (block syntax) and, for some
// nesting modes, `root_block_device = [...]` (attribute syntax). Treating the
// name as valid in both positions avoids flagging a legal spelling.
func collectBlock(b *tfBlock, path string, res *PackResource) {
	names := make([]string, 0, len(b.Attributes)+len(b.BlockTypes))
	for name := range b.Attributes {
		names = append(names, name)
	}
	for name := range b.BlockTypes {
		names = append(names, name)
	}

	if path == "" {
		res.TopLevel = append(res.TopLevel, names...)
	} else {
		res.NestedBlocks[path] = names
	}

	for name, bt := range b.BlockTypes {
		if bt.Block == nil {
			continue
		}
		child := name
		if path != "" {
			child = path + "." + name
		}
		collectBlock(bt.Block, child, res)
	}
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
