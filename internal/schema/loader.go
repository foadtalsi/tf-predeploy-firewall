// Package schema holds curated, statically-known facts about the AWS
// provider (allowed attributes, ForceNew attributes, critical stateful
// resource types) needed to detect risk patterns without a terraform plan.
// All knowledge lives in the JSON files under data/ so it can be extended
// or replaced (e.g. with a generated full-provider dump) without touching
// rule logic.
package schema

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed data/*.json
var dataFS embed.FS

// ForceNewSpec describes which attributes (top-level and/or nested-block)
// trigger a destroy+recreate for a resource type.
type ForceNewSpec struct {
	// TopLevel lists top-level attribute names that are ForceNew.
	TopLevel []string
	// NestedBlocks maps block_type -> ForceNew attribute names inside that block.
	NestedBlocks map[string][]string
}

// ResourceSchema describes the allowed attributes for a resource type, at
// both the top level and inside named nested blocks.
type ResourceSchema struct {
	// TopLevel lists allowed top-level attribute names.
	TopLevel []string
	// NestedBlocks maps block_type -> allowed attribute names inside that block.
	// Block types not listed here are not validated (avoid false positives on
	// uncurated blocks).
	NestedBlocks map[string][]string
}

// PricingSpec is the curated approximate monthly cost for a resource type.
// A type may have a flat Base cost, and/or a cost that depends on the value
// of a single pricing-driving Attribute (e.g. instance_type). ByAttribute
// misses fall back to Default. All figures are coarse USD/month estimates.
type PricingSpec struct {
	Base        float64            // flat monthly cost regardless of attributes
	Attribute   string             // attribute whose value drives cost, if any
	ByAttribute map[string]float64 // attribute value -> monthly cost
	Default     float64            // used when Attribute is set but the value isn't in ByAttribute
}

// MonthlyCost returns the estimated monthly USD cost for a resource of this
// type, given its attribute values (as strings). Base and attribute-driven
// costs add together, so e.g. a resource with both a flat base and a
// per-size price is handled.
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

// AWS holds the loaded static knowledge base. Construct with Load().
type AWS struct {
	// ResourceSchemas maps resource_type -> allowed attributes (top-level + nested).
	// Resource types absent from this map are skipped by the unknown-attribute
	// rule (we'd rather under-detect than spam false positives on unmapped types).
	ResourceSchemas map[string]*ResourceSchema

	// ForceNewAttrs maps resource_type -> ForceNew spec (top-level + nested blocks).
	ForceNewAttrs map[string]*ForceNewSpec

	// CriticalStatefulResources is the set of resource types expected to
	// carry lifecycle { prevent_destroy = true }.
	CriticalStatefulResources map[string]bool

	// Pricing maps resource_type -> approximate monthly cost spec. Resource
	// types absent here contribute $0 to cost estimates (unknown = ignored,
	// same under-detect-over-spam philosophy as the other maps).
	Pricing map[string]*PricingSpec
}

func Load() (*AWS, error) {
	resourceSchemas, err := loadResourceSchemas("data/aws_resource_schemas.json")
	if err != nil {
		return nil, fmt.Errorf("loading aws_resource_schemas.json: %w", err)
	}
	forceNew, err := loadForceNewAttrs("data/aws_forcenew_attrs.json")
	if err != nil {
		return nil, fmt.Errorf("loading aws_forcenew_attrs.json: %w", err)
	}

	criticalRaw, err := dataFS.ReadFile("data/critical_stateful_resources.json")
	if err != nil {
		return nil, fmt.Errorf("loading critical_stateful_resources.json: %w", err)
	}
	var critical struct {
		ResourceTypes []string `json:"resource_types"`
	}
	if err := json.Unmarshal(criticalRaw, &critical); err != nil {
		return nil, fmt.Errorf("parsing critical_stateful_resources.json: %w", err)
	}
	criticalSet := make(map[string]bool, len(critical.ResourceTypes))
	for _, t := range critical.ResourceTypes {
		criticalSet[t] = true
	}

	pricing, err := loadPricing("data/aws_pricing.json")
	if err != nil {
		return nil, fmt.Errorf("loading aws_pricing.json: %w", err)
	}

	return &AWS{
		ResourceSchemas:           resourceSchemas,
		ForceNewAttrs:             forceNew,
		CriticalStatefulResources: criticalSet,
		Pricing:                   pricing,
	}, nil
}

// loadPricing reads aws_pricing.json into per-resource-type PricingSpecs.
func loadPricing(path string) (map[string]*PricingSpec, error) {
	raw, err := dataFS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string]*PricingSpec, len(m))
	for k, v := range m {
		if k == "_comment" {
			continue
		}
		var obj struct {
			Base        float64            `json:"base"`
			Attribute   string             `json:"attribute"`
			ByAttribute map[string]float64 `json:"by_attribute"`
			Default     float64            `json:"default"`
		}
		if err := json.Unmarshal(v, &obj); err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		out[k] = &PricingSpec{
			Base:        obj.Base,
			Attribute:   obj.Attribute,
			ByAttribute: obj.ByAttribute,
			Default:     obj.Default,
		}
	}
	return out, nil
}

// loadForceNewAttrs reads aws_forcenew_attrs.json which supports two formats
// per resource type:
//
//	"aws_instance": ["ami", "subnet_id"]          ← top-level only (legacy)
//	"aws_instance": {
//	    "top_level": ["ami"],
//	    "nested_blocks": { "root_block_device": ["volume_type"] }
//	}
func loadForceNewAttrs(path string) (map[string]*ForceNewSpec, error) {
	raw, err := dataFS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string]*ForceNewSpec, len(m))
	for k, v := range m {
		if k == "_comment" {
			continue
		}
		spec := &ForceNewSpec{NestedBlocks: map[string][]string{}}
		// Try array form first (legacy / simple).
		var list []string
		if json.Unmarshal(v, &list) == nil {
			spec.TopLevel = list
			out[k] = spec
			continue
		}
		// Object form with optional top_level + nested_blocks.
		var obj struct {
			TopLevel     []string            `json:"top_level"`
			NestedBlocks map[string][]string `json:"nested_blocks"`
		}
		if err := json.Unmarshal(v, &obj); err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		spec.TopLevel = obj.TopLevel
		if obj.NestedBlocks != nil {
			spec.NestedBlocks = obj.NestedBlocks
		}
		out[k] = spec
	}
	return out, nil
}

// loadResourceSchemas reads aws_resource_schemas.json. Supports two formats:
//
//	"aws_s3_bucket": ["bucket", "tags", ...]                   ← top-level only (legacy)
//	"aws_instance": {
//	    "top_level": ["ami", "instance_type", ...],
//	    "nested_blocks": { "root_block_device": ["volume_type", ...] }
//	}
func loadResourceSchemas(path string) (map[string]*ResourceSchema, error) {
	raw, err := dataFS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string]*ResourceSchema, len(m))
	for k, v := range m {
		if k == "_comment" {
			continue
		}
		schema := &ResourceSchema{NestedBlocks: map[string][]string{}}
		var list []string
		if json.Unmarshal(v, &list) == nil {
			schema.TopLevel = list
			out[k] = schema
			continue
		}
		var obj struct {
			TopLevel     []string            `json:"top_level"`
			NestedBlocks map[string][]string `json:"nested_blocks"`
		}
		if err := json.Unmarshal(v, &obj); err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		schema.TopLevel = obj.TopLevel
		if obj.NestedBlocks != nil {
			schema.NestedBlocks = obj.NestedBlocks
		}
		out[k] = schema
	}
	return out, nil
}
