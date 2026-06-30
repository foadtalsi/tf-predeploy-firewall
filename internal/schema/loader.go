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

// AWS holds the loaded static knowledge base. Construct with Load().
type AWS struct {
	// ResourceSchemas maps resource_type -> allowed top-level attribute names.
	// Resource types absent from this map are skipped by the unknown-attribute
	// rule (we'd rather under-detect than spam false positives on unmapped types).
	ResourceSchemas map[string][]string

	// ForceNewAttrs maps resource_type -> attribute names that trigger
	// destroy+recreate when changed.
	ForceNewAttrs map[string][]string

	// CriticalStatefulResources is the set of resource types expected to
	// carry lifecycle { prevent_destroy = true }.
	CriticalStatefulResources map[string]bool
}

func Load() (*AWS, error) {
	resourceSchemas, err := loadStringListMap("data/aws_resource_schemas.json")
	if err != nil {
		return nil, fmt.Errorf("loading aws_resource_schemas.json: %w", err)
	}
	forceNew, err := loadStringListMap("data/aws_forcenew_attrs.json")
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
		ResourceSchemas:            resourceSchemas,
		ForceNewAttrs:              forceNew,
		CriticalStatefulResources:  criticalSet,
	}, nil
}

// loadStringListMap reads a JSON object of resource_type -> []string,
// ignoring any "_comment" key.
func loadStringListMap(path string) (map[string][]string, error) {
	raw, err := dataFS.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(m))
	for k, v := range m {
		if k == "_comment" {
			continue
		}
		var list []string
		if err := json.Unmarshal(v, &list); err != nil {
			return nil, fmt.Errorf("key %s: %w", k, err)
		}
		out[k] = list
	}
	return out, nil
}
