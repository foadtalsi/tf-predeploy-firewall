// Command genpack builds the scanner's rule packs from authoritative sources
// instead of hand-curated lists.
//
//	# 1. the complete attribute surface, straight from the provider
//	mkdir -p /tmp/awsschema && cd /tmp/awsschema
//	cat > main.tf <<'EOF'
//	terraform { required_providers { aws = { source = "hashicorp/aws", version = "~> 6.0" } } }
//	EOF
//	terraform init && terraform providers schema -json > schema.json
//
//	# 2. ForceNew flags, which that JSON does not carry
//	git clone --depth 1 --filter=blob:none --sparse \
//	    https://github.com/hashicorp/terraform-provider-aws.git /tmp/tpaws
//	cd /tmp/tpaws && git sparse-checkout set internal/service names
//
//	# 3. build both packs
//	go run ./cmd/genpack \
//	    --provider-schema /tmp/awsschema/schema.json \
//	    --provider-src    /tmp/tpaws \
//	    --provider-version 6.18.0
//
// The base pack is embedded in the scanner binary and stays free; the full
// pack is published to the control plane and served to licensed orgs. Both
// are cut from the same generated data, so the free and paid tiers can never
// disagree about the same resource type — the paid one simply covers more.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

func main() {
	var (
		provider     = flag.String("provider", "aws", "provider short name (aws, azurerm) — names the pack, and defaults the address, curated-file and output paths")
		schemaPath   = flag.String("provider-schema", "", "path to `terraform providers schema -json` output (required)")
		srcPath      = flag.String("provider-src", "", "path to a provider source checkout, for ForceNew extraction (optional but strongly recommended; the extractor understands SDKv2 and Plugin Framework layouts)")
		providerAddr = flag.String("provider-address", "", "provider address inside the schema JSON (default registry.terraform.io/hashicorp/<provider>)")
		providerVer  = flag.String("provider-version", "", "provider version these packs describe, recorded in the pack (required)")
		curatedDir   = flag.String("curated-dir", "", "directory holding the hand-curated overlays (default internal/schema/curated/<provider>; aws keeps its historical flat layout)")
		baseOut      = flag.String("base-out", "", "output path for the embedded free base pack (default internal/schema/data/pack_<provider>_base.json.gz)")
		fullOut      = flag.String("full-out", "", "output path for the full pack served by the control plane (default dist/pack_<provider>_full.json.gz)")
		indexOut     = flag.String("emit-forcenew-index", "", "write the extracted ForceNew index to this path as JSON and exit, without generating packs. Needs only --provider-src. The index is the extractor's whole output, and having it as a file is what lets it be reviewed, diffed between provider releases, and consumed by a generator that isn't this one — see index.go.")
	)
	flag.Parse()

	// Extractor-only mode. Deliberately before the --provider-schema check:
	// extraction reads the provider's Go source and has nothing to do with the
	// terraform-generated schema JSON, so requiring one to produce the other
	// would be a coupling that isn't there.
	if *indexOut != "" {
		if *srcPath == "" {
			fmt.Fprintln(os.Stderr, "genpack: --emit-forcenew-index needs --provider-src")
			os.Exit(2)
		}
		idx, err := extractorFor(*provider)(*srcPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "genpack: %v\n", err)
			os.Exit(1)
		}
		if err := writeForceNewIndex(*indexOut, *provider, *providerVer, idx); err != nil {
			fmt.Fprintf(os.Stderr, "genpack: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s (SDKv2 %d/%d resolved, Framework %d/%d resolved, %d resource types)\n",
			*indexOut, idx.SDKResourcesResolved, idx.SDKResourcesSeen,
			idx.FrameworkResolved, idx.FrameworkSeen, len(idx.TopLevel)+len(idx.Nested))
		return
	}

	if *schemaPath == "" || *providerVer == "" {
		flag.Usage()
		os.Exit(2)
	}

	// Everything defaults from the provider name so generating a second
	// provider's packs is one flag, not five paths kept consistent by hand.
	if *providerAddr == "" {
		*providerAddr = "registry.terraform.io/hashicorp/" + *provider
	}
	if *curatedDir == "" {
		if *provider == "aws" {
			*curatedDir = "internal/schema/curated" // historical flat layout
		} else {
			*curatedDir = filepath.Join("internal/schema/curated", *provider)
		}
	}
	if *baseOut == "" {
		*baseOut = fmt.Sprintf("internal/schema/data/pack_%s_base.json.gz", *provider)
	}
	if *fullOut == "" {
		*fullOut = fmt.Sprintf("dist/pack_%s_full.json.gz", *provider)
	}

	if err := run(*provider, *schemaPath, *srcPath, *providerAddr, *providerVer, *curatedDir, *baseOut, *fullOut); err != nil {
		fmt.Fprintf(os.Stderr, "genpack: %v\n", err)
		os.Exit(1)
	}
}

func run(provider, schemaPath, srcPath, providerAddr, providerVer, curatedDir, baseOut, fullOut string) error {
	// --- 1. attribute surface -------------------------------------------
	resources, err := loadProviderSchema(schemaPath, providerAddr)
	if err != nil {
		return err
	}
	fmt.Printf("attribute surface: %d resource types\n", len(resources))

	// --- 2. ForceNew ------------------------------------------------------
	if srcPath != "" {
		idx, err := extractorFor(provider)(srcPath)
		if err != nil {
			return err
		}
		applyForceNew(resources, idx)

		covered := 0
		for _, r := range resources {
			if len(r.ForceNewTopLevel) > 0 || len(r.ForceNewNested) > 0 {
				covered++
			}
		}
		fmt.Printf("ForceNew: SDKv2 %d/%d resolved, Framework %d/%d resolved, %d resource types carry ForceNew data\n",
			idx.SDKResourcesResolved, idx.SDKResourcesSeen,
			idx.FrameworkResolved, idx.FrameworkSeen, covered)
	} else {
		fmt.Println("ForceNew: skipped (--provider-src not given)")
	}

	// --- 3. curated overlays ---------------------------------------------
	critical, err := readStringList(filepath.Join(curatedDir, "critical_stateful_resources.json"), "resource_types")
	if err != nil {
		return err
	}
	unknownCritical := 0
	for _, t := range critical {
		r, ok := resources[t]
		if !ok {
			// A curated type the provider no longer ships: worth knowing
			// about, since the curated list is the one thing still written
			// by hand.
			fmt.Fprintf(os.Stderr, "genpack: curated critical type %q is not in the provider schema\n", t)
			unknownCritical++
			continue
		}
		r.Critical = true
	}
	fmt.Printf("critical stateful: %d types (%d unmatched)\n", len(critical)-unknownCritical, unknownCritical)

	pricing, err := readPricing(filepath.Join(curatedDir, provider+"_pricing.json"))
	if err != nil {
		return err
	}
	for t, p := range pricing {
		if r, ok := resources[t]; ok {
			r.Pricing = p
		}
	}
	fmt.Printf("pricing: %d types\n", len(pricing))

	// --- 4. write packs ---------------------------------------------------
	full := &Pack{
		FormatVersion:   PackFormatVersion,
		ID:              provider + "-full",
		Provider:        provider,
		ProviderVersion: providerVer,
		Resources:       resources,
	}

	baseTypes, err := readStringList(filepath.Join(curatedDir, "base_pack_types.json"), "resource_types")
	if err != nil {
		return err
	}
	sort.Strings(baseTypes)
	base := full.subset(provider+"-base", baseTypes)

	for _, path := range []string{baseOut, fullOut} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
	}
	if err := base.writeGzipJSON(baseOut); err != nil {
		return fmt.Errorf("writing base pack: %w", err)
	}
	if err := full.writeGzipJSON(fullOut); err != nil {
		return fmt.Errorf("writing full pack: %w", err)
	}

	baseInfo, _ := os.Stat(baseOut)
	fullInfo, _ := os.Stat(fullOut)
	fmt.Printf("wrote %s (%d types, %.0f KB)\n", baseOut, len(base.Resources), float64(baseInfo.Size())/1024)
	fmt.Printf("wrote %s (%d types, %.0f KB)\n", fullOut, len(full.Resources), float64(fullInfo.Size())/1024)
	return nil
}

// applyForceNew merges extracted ForceNew data onto the attribute surface,
// dropping anything that doesn't correspond to a real argument. A ForceNew
// entry for an argument the provider schema doesn't declare would mean the
// extractor misread the source, and acting on it could block a PR over an
// argument that doesn't exist.
func applyForceNew(resources map[string]*PackResource, idx *forceNewIndex) {
	for rType, attrs := range idx.TopLevel {
		r, ok := resources[rType]
		if !ok {
			continue
		}
		valid := toSet(r.TopLevel)
		for _, a := range attrs {
			if valid[a] {
				r.ForceNewTopLevel = append(r.ForceNewTopLevel, a)
			}
		}
		r.ForceNewTopLevel = dedupe(r.ForceNewTopLevel)
	}

	for rType, byPath := range idx.Nested {
		r, ok := resources[rType]
		if !ok {
			continue
		}
		for path, attrs := range byPath {
			declared, ok := r.NestedBlocks[path]
			if !ok {
				continue
			}
			valid := toSet(declared)
			var keep []string
			for _, a := range attrs {
				if valid[a] {
					keep = append(keep, a)
				}
			}
			if len(keep) == 0 {
				continue
			}
			if r.ForceNewNested == nil {
				r.ForceNewNested = map[string][]string{}
			}
			r.ForceNewNested[path] = dedupe(append(r.ForceNewNested[path], keep...))
		}
	}
}

func toSet(list []string) map[string]bool {
	s := make(map[string]bool, len(list))
	for _, v := range list {
		s[v] = true
	}
	return s
}

func readStringList(path, field string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	var out []string
	if err := json.Unmarshal(doc[field], &out); err != nil {
		return nil, fmt.Errorf("parsing %s field %q: %w", path, field, err)
	}
	return out, nil
}

func readPricing(path string) (map[string]*PackPricing, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	out := map[string]*PackPricing{}
	for k, v := range doc {
		if k == "_comment" {
			continue
		}
		var p PackPricing
		if err := json.Unmarshal(v, &p); err != nil {
			return nil, fmt.Errorf("parsing pricing for %s: %w", k, err)
		}
		out[k] = &p
	}
	return out, nil
}
