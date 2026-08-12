package schema

import "testing"

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
		if _, ok := aws.ResourceSchemas[rt]; !ok {
			t.Errorf("ResourceSchemas missing %s", rt)
		}
	}

	mustHaveForceNew := []string{
		"aws_db_instance", "aws_rds_cluster", "aws_instance", "aws_ebs_volume",
		"aws_elasticache_replication_group", "aws_kms_key", "aws_sqs_queue",
	}
	for _, rt := range mustHaveForceNew {
		if _, ok := aws.ForceNewAttrs[rt]; !ok {
			t.Errorf("ForceNewAttrs missing %s", rt)
		}
	}

	mustBeCritical := []string{
		"aws_db_instance", "aws_rds_cluster", "aws_dynamodb_table",
		"aws_elasticache_replication_group", "aws_secretsmanager_secret",
	}
	for _, rt := range mustBeCritical {
		if !aws.CriticalStatefulResources[rt] {
			t.Errorf("CriticalStatefulResources missing %s", rt)
		}
	}
}

func TestLoad_AllowedAttrsNotEmpty(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for rt, schema := range aws.ResourceSchemas {
		if len(schema.TopLevel) == 0 {
			t.Errorf("ResourceSchemas[%s] has an empty top-level attribute list", rt)
		}
	}
}

func TestLoad_Pricing(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Attribute-driven: an EC2 instance priced by instance_type.
	ec2 := aws.Pricing["aws_instance"]
	if ec2 == nil {
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
	nat := aws.Pricing["aws_nat_gateway"]
	if nat == nil || nat.MonthlyCost("") != 32 {
		t.Errorf("expected aws_nat_gateway flat base 32, got %v", nat)
	}
}
