package planjson

import (
	"os"
	"testing"
)

func TestLoad_SamplePlan(t *testing.T) {
	pf, err := Load("../../testdata/plans/sample_plan.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(pf.ResourceChanges) != 4 {
		t.Fatalf("expected 4 resource changes, got %d", len(pf.ResourceChanges))
	}

	byAddr := map[string]ResourceChange{}
	for _, rc := range pf.ResourceChanges {
		byAddr[rc.Address] = rc
	}

	if !byAddr["aws_db_instance.prod"].Change.IsReplace() {
		t.Error("expected aws_db_instance.prod to be a replace (delete+create)")
	}
	if !byAddr["aws_s3_bucket.logs"].Change.IsDestroyOnly() {
		t.Error("expected aws_s3_bucket.logs to be destroy-only")
	}
	if !byAddr["aws_security_group.web"].Change.IsPureUpdate() {
		t.Error("expected aws_security_group.web to be a pure update")
	}
	if !byAddr["aws_iam_role.app"].Change.IsNoOp() {
		t.Error("expected aws_iam_role.app to be a no-op")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load("../../testdata/plans/does_not_exist.json")
	if err == nil {
		t.Fatal("expected an error for a missing file")
	}
}

func TestLoad_MalformedJSON(t *testing.T) {
	path := t.TempDir() + "/bad.json"
	if err := os.WriteFile(path, []byte("{not valid json"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}
