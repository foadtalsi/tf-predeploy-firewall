package main

import (
	"reflect"
	"testing"
)

// The fixture covers each registration shape the Google providers use: a plain
// SDKv2 resource, nested blocks built by helper functions, an IAM resource whose
// schema is merged from two packages, a data source that must be ignored, and a
// Plugin Framework resource.
func TestExtractForceNewGoogle(t *testing.T) {
	index, err := extractForceNewGoogle("testdata/google")
	if err != nil {
		t.Fatalf("extraction: %v", err)
	}

	if got, want := index.TopLevel["google_storage_bucket"], []string{"name"}; !reflect.DeepEqual(got, want) {
		t.Errorf("google_storage_bucket top-level ForceNew = %v, want %v", got, want)
	}
	if got, want := index.Nested["google_storage_bucket"]["custom_placement_config"], []string{"data_locations"}; !reflect.DeepEqual(got, want) {
		t.Errorf("schema built by a helper: ForceNew = %v, want %v", got, want)
	}
	if got, want := index.Nested["google_storage_bucket"]["retention_policy"], []string{"is_locked"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Elem built by a helper: ForceNew = %v, want %v", got, want)
	}

	// Both halves of the merged IAM schema: role and member from
	// tpgiamresource, project from the service package.
	got := dedupe(append([]string(nil), index.TopLevel["google_project_iam_member"]...))
	want := []string{"role", "member", "project"}
	if !sameElements(got, want) {
		t.Errorf("google_project_iam_member ForceNew = %v, want %v", got, want)
	}

	if got, want := index.TopLevel["google_storage_notification"], []string{"bucket"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Framework resource ForceNew = %v, want %v", got, want)
	}

	// The data source registration must not count as a resource.
	if index.SDKResourcesSeen != 2 || index.SDKResourcesResolved != 2 {
		t.Errorf("SDKv2 resources resolved = %d/%d, want 2/2", index.SDKResourcesResolved, index.SDKResourcesSeen)
	}
	if index.FrameworkSeen != 1 || index.FrameworkResolved != 1 {
		t.Errorf("Framework resources resolved = %d/%d, want 1/1", index.FrameworkResolved, index.FrameworkSeen)
	}
}

// The AWS extractor must not follow helper functions: that behaviour is opt-in
// for the Google providers so the AWS and azurerm packs do not change.
func TestSchemaHelpersAreNotFollowedByDefault(t *testing.T) {
	servicePackage, err := parsePackage("testdata/google/google/services/storage")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	index := newForceNewIndex()
	function := servicePackage.funcs["ResourceStorageBucket"]
	walkSDKSchemaMap(resolveSDKSchemaMap(function, servicePackage), "", "google_storage_bucket", servicePackage, nil, index)
	if _, present := index.Nested["google_storage_bucket"]; present {
		t.Errorf("nested ForceNew from helpers was recorded without opting in: %v", index.Nested)
	}
}

func sameElements(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[string]int{}
	for _, value := range a {
		counts[value]++
	}
	for _, value := range b {
		counts[value]--
	}
	for _, count := range counts {
		if count != 0 {
			return false
		}
	}
	return true
}
