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

	return &AWS{
		ResourceSchemas:           resourceSchemas,
		ForceNewAttrs:             forceNew,
		CriticalStatefulResources: criticalSet,
	}, nil
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
