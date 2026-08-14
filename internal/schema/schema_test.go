package schema

import (
	"bytes"
	"compress/gzip"
	"testing"
)

func TestLoad_HasExpectedResourceTypes(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	mustHaveSchema := []string{
		"aws_db_instance", "aws_rds_cluster", "aws_instance", "aws_s3_bucket",
		"aws_security_group", "aws_iam_role", "aws_lambda_function",
		"aws_eks_cluster", "aws_ecs_service", "aws_lb", "aws_dynamodb_table",
		"aws_elasticache_replication_group", "aws_secretsmanager_secret",
	}
	for _, rt := range mustHaveSchema {
		if _, ok := aws.ResourceSchema(rt); !ok {
			t.Errorf("base pack is missing the argument surface for %s", rt)
		}
	}

	mustHaveForceNew := []string{
		"aws_db_instance", "aws_rds_cluster", "aws_instance", "aws_ebs_volume",
		"aws_elasticache_replication_group", "aws_kms_key", "aws_sqs_queue",
	}
	for _, rt := range mustHaveForceNew {
		if _, ok := aws.ForceNew(rt); !ok {
			t.Errorf("base pack is missing ForceNew data for %s", rt)
		}
	}

	mustBeCritical := []string{
		"aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
		"aws_elasticache_replication_group", "aws_secretsmanager_secret",
	}
	for _, rt := range mustBeCritical {
		if !aws.IsCritical(rt) {
			t.Errorf("%s should be marked critical/stateful", rt)
		}
	}
}

// The generated surface must actually be complete, not merely present. These
// arguments are exactly the kind that a hand-curated list kept missing, and
// each omission was a false "hallucinated attribute" finding at severity
// high — i.e. a blocked PR on valid Terraform.
func TestResourceSchema_CoversRealWorldArguments(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := map[string][]string{
		"aws_instance": {
			"ami", "instance_type", "launch_template", "cpu_options",
			"hibernation", "placement_group", "network_interface",
			"capacity_reservation_specification", "maintenance_options",
			// Terraform's own meta-arguments are valid in every resource.
			"count", "for_each", "lifecycle", "depends_on", "provider",
		},
		"aws_s3_bucket":       {"bucket", "force_destroy", "tags"},
		"aws_lambda_function": {"function_name", "runtime", "architectures", "logging_config"},
	}

	for rType, args := range cases {
		rs, ok := aws.ResourceSchema(rType)
		if !ok {
			t.Fatalf("no schema for %s", rType)
		}
		valid := make(map[string]bool, len(rs.TopLevel))
		for _, a := range rs.TopLevel {
			valid[a] = true
		}
		for _, a := range args {
			if !valid[a] {
				t.Errorf("%s: argument %q missing from the pack — would be flagged as hallucinated", rType, a)
			}
		}
	}
}

// ForceNew data drives the rule that warns about destroy+recreate, so a wrong
// entry is worse than a missing one. Spot-check against the provider's
// documented behaviour.
func TestForceNew_KnownAttributes(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	want := map[string][]string{
		"aws_db_instance":    {"engine", "db_name", "username", "storage_encrypted", "availability_zone"},
		"aws_instance":       {"ami", "availability_zone", "key_name", "placement_group"},
		"aws_ebs_volume":     {"availability_zone", "encrypted", "snapshot_id"},
		"aws_dynamodb_table": {"hash_key", "range_key", "name"},
	}

	for rType, attrs := range want {
		spec, ok := aws.ForceNew(rType)
		if !ok {
			t.Fatalf("no ForceNew data for %s", rType)
		}
		got := make(map[string]bool, len(spec.TopLevel))
		for _, a := range spec.TopLevel {
			got[a] = true
		}
		for _, a := range attrs {
			if !got[a] {
				t.Errorf("%s: %q should be ForceNew", rType, a)
			}
		}
	}

	// Something plainly updatable in place must NOT be reported as ForceNew,
	// or every tag edit would warn about a destroy.
	spec, _ := aws.ForceNew("aws_instance")
	for _, a := range spec.TopLevel {
		if a == "tags" || a == "instance_type" {
			t.Errorf("aws_instance: %q is updatable in place and must not be ForceNew", a)
		}
	}
}

// Every ForceNew argument has to exist in the same pack's argument surface.
// A ForceNew entry naming an argument the provider doesn't declare would mean
// the generator misread the provider source.
func TestForceNew_ReferencesRealArguments(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	for rType := range aws.packs[0].Resources {
		spec, ok := aws.ForceNew(rType)
		if !ok {
			continue
		}
		rs, ok := aws.ResourceSchema(rType)
		if !ok {
			t.Errorf("%s has ForceNew data but no argument surface", rType)
			continue
		}
		valid := make(map[string]bool, len(rs.TopLevel))
		for _, a := range rs.TopLevel {
			valid[a] = true
		}
		for _, a := range spec.TopLevel {
			if !valid[a] {
				t.Errorf("%s: ForceNew argument %q is not in the argument surface", rType, a)
			}
		}
		for path, attrs := range spec.NestedBlocks {
			declared, ok := rs.NestedBlocks[path]
			if !ok {
				t.Errorf("%s: ForceNew block path %q is not in the argument surface", rType, path)
				continue
			}
			validNested := make(map[string]bool, len(declared))
			for _, a := range declared {
				validNested[a] = true
			}
			for _, a := range attrs {
				if !validNested[a] {
					t.Errorf("%s.%s: ForceNew argument %q is not declared in that block", rType, path, a)
				}
			}
		}
	}
}

func TestLoad_AllowedAttrsNotEmpty(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for rt := range aws.packs[0].Resources {
		rs, ok := aws.ResourceSchema(rt)
		if !ok || len(rs.TopLevel) == 0 {
			t.Errorf("%s has an empty top-level argument list", rt)
		}
	}
}

func TestLoad_Pricing(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Attribute-driven: an EC2 instance priced by instance_type.
	ec2, ok := aws.PricingFor("aws_instance")
	if !ok {
		t.Fatal("expected pricing for aws_instance")
	}
	if got := ec2.MonthlyCost("m5.xlarge"); got != 140 {
		t.Errorf("m5.xlarge monthly cost = %v, want 140", got)
	}
	// Unknown size falls back to default, not zero.
	if got := ec2.MonthlyCost("some-future-size"); got != ec2.Default || got == 0 {
		t.Errorf("unknown size should fall back to default %v, got %v", ec2.Default, got)
	}

	// Flat base: NAT gateway has no attribute.
	nat, ok := aws.PricingFor("aws_nat_gateway")
	if !ok || nat.MonthlyCost("") != 32 {
		t.Errorf("expected aws_nat_gateway flat base 32, got %v", nat)
	}
}

func TestCoverage_BasePackOnly(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	c := aws.Coverage()
	if c.Extended {
		t.Error("a base-only load must not report extended coverage")
	}
	// One base pack per embedded provider; pinning the exact list here would
	// make every new free-tier provider a test failure, which is backwards.
	found := false
	for _, p := range c.Packs {
		if p == "aws-base" {
			found = true
		}
	}
	if !found {
		t.Errorf("Packs = %v, must include aws-base", c.Packs)
	}
	if c.ResourceTypes == 0 {
		t.Error("base pack reports zero resource types")
	}
	if c.VersionOf("aws") == "" {
		t.Error("pack does not record which provider version it describes")
	}
}

// An overlaid pack must win over the base pack for a type they share, and add
// the types the base pack never had.
func TestLoadWith_OverlayTakesPrecedence(t *testing.T) {
	overlay := makePack(t, `{
		"format_version": 1,
		"id": "aws-full",
		"provider": "aws",
		"provider_version": "9.9.9",
		"resources": {
			"aws_instance": {"top_level": ["only_this_one"]},
			"aws_brand_new_type": {"top_level": ["alpha"], "critical": true}
		}
	}`)

	aws, errs := LoadWith(overlay)
	if len(errs) != 0 {
		t.Fatalf("LoadWith: %v", errs)
	}

	rs, ok := aws.ResourceSchema("aws_instance")
	if !ok || len(rs.TopLevel) != 1 || rs.TopLevel[0] != "only_this_one" {
		t.Errorf("overlay should shadow the base pack, got %v", rs)
	}
	if !aws.IsCritical("aws_brand_new_type") {
		t.Error("overlay-only type not visible")
	}
	// Types only the base pack knows about are still reachable.
	if _, ok := aws.ResourceSchema("aws_s3_bucket"); !ok {
		t.Error("overlay hid an unrelated base-pack type")
	}

	c := aws.Coverage()
	if !c.Extended {
		t.Error("Coverage should report extended after an overlay")
	}
}

// A corrupt or unreadable extended pack degrades coverage; it never prevents
// a scan. The whole delivery path is built on that promise.
func TestLoadWith_BadPackDoesNotBreakLoading(t *testing.T) {
	aws, errs := LoadWith(bytes.NewReader([]byte("not a gzip pack")))
	if len(errs) != 1 {
		t.Fatalf("expected 1 error, got %v", errs)
	}
	if aws == nil {
		t.Fatal("a bad overlay must not prevent the base pack from loading")
	}
	if _, ok := aws.ResourceSchema("aws_instance"); !ok {
		t.Error("base pack unusable after a bad overlay")
	}
	if aws.Coverage().Extended {
		t.Error("a rejected pack must not count as extended coverage")
	}
}

func TestParsePack_RejectsUnknownFormatVersion(t *testing.T) {
	_, errs := LoadWith(makePack(t, `{"format_version": 99, "id": "future", "resources": {}}`))
	if len(errs) != 1 {
		t.Fatalf("expected the pack to be rejected, got %v", errs)
	}
}

func makePack(t *testing.T, jsonBody string) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(jsonBody)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}
