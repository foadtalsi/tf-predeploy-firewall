// Extract AWS ForceNew metadata from SDK and Framework schemas separately. Unresolved
// expressions remain coverage gaps rather than guessed detections.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var (
	sdkResourceRe       = regexp.MustCompile(`@SDKResource\("([a-z0-9_]+)"`)
	frameworkResourceRe = regexp.MustCompile(`@FrameworkResource\("([a-z0-9_]+)"`)
)

// forceNewIndex is the extraction result: resource type -> ForceNew paths.
type forceNewIndex struct {
	// TopLevel maps resource type -> ForceNew top-level argument names.
	TopLevel map[string][]string
	// Nested maps resource type -> dotted block path -> ForceNew names.
	Nested map[string]map[string][]string

	// Stats, reported so pack coverage is a measured number rather than a
	// claim.
	SDKResourcesSeen     int
	SDKResourcesResolved int
	FrameworkSeen        int
	FrameworkResolved    int
}

func newForceNewIndex() *forceNewIndex {
	return &forceNewIndex{
		TopLevel: map[string][]string{},
		Nested:   map[string]map[string][]string{},
	}
}

func (index *forceNewIndex) add(resourceType, path, attr string) {
	if path == "" {
		index.TopLevel[resourceType] = append(index.TopLevel[resourceType], attr)
		return
	}
	if index.Nested[resourceType] == nil {
		index.Nested[resourceType] = map[string][]string{}
	}
	index.Nested[resourceType][path] = append(index.Nested[resourceType][path], attr)
}

// extractForceNew walks every service package under <src>/internal/service.
func extractForceNew(sourceRoot string) (*forceNewIndex, error) {
	providerConstants, err := loadStringConsts(filepath.Join(sourceRoot, "names"))
	if err != nil {
		return nil, fmt.Errorf("loading names constants: %w", err)
	}

	serviceRoot := filepath.Join(sourceRoot, "internal", "service")
	entries, err := os.ReadDir(serviceRoot)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", serviceRoot, err)
	}

	index := newForceNewIndex()
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		servicePackage, err := parsePackage(filepath.Join(serviceRoot, e.Name()))
		if err != nil {
			// A package we can't parse is a gap in coverage, not a reason to
			// abandon the other 270.
			fmt.Fprintf(os.Stderr, "forcenew-extractor: skipping %s: %v\n", e.Name(), err)
			continue
		}
		collectSDKResources(servicePackage, providerConstants, index)
		collectFrameworkResources(servicePackage, providerConstants, index)
	}
	return index, nil
}
