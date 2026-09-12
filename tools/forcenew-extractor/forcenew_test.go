package main

import (
	"reflect"
	"testing"
)

// A small provider fixture checks supported extraction forms and false positives without
// cloning a full provider repository.
func TestExtractForceNew(t *testing.T) {
	index, err := extractForceNew("testdata/aws")
	if err != nil {
		t.Fatalf("extraction: %v", err)
	}

	wantTopLevel := []string{"identifier", "restore_to_point_in_time"}
	if got := index.TopLevel["aws_db_instance"]; !reflect.DeepEqual(got, wantTopLevel) {
		t.Errorf("top-level ForceNew attributes = %v, want %v", got, wantTopLevel)
	}

	// The nested block and its attributes can each be ForceNew; retain both.
	wantNested := []string{"source_db_instance_identifier"}
	if got := index.Nested["aws_db_instance"]["restore_to_point_in_time"]; !reflect.DeepEqual(got, wantNested) {
		t.Errorf("nested ForceNew attributes = %v, want %v", got, wantNested)
	}

	// allocated_storage is not ForceNew and must not be reported as a replacement trigger.
	for _, name := range index.TopLevel["aws_db_instance"] {
		if name == "allocated_storage" {
			t.Error("allocated_storage must not be marked ForceNew")
		}
	}

	// A resolved resource with no ForceNew fields contributes no index entry, but still counts
	// toward successful schema resolution.
	if _, present := index.TopLevel["aws_instance"]; present {
		t.Error("aws_instance has no ForceNew fields and must not appear in the index")
	}
	if index.SDKResourcesSeen != 2 {
		t.Errorf("SDKv2 resources seen = %d, want 2", index.SDKResourcesSeen)
	}
	if index.SDKResourcesResolved != 2 {
		t.Errorf("SDKv2 resources resolved = %d, want 2", index.SDKResourcesResolved)
	}
}
