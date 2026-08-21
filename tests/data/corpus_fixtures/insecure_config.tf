# Positive corpus for the insecure_config group: public_exposure,
# encryption_disabled, permissive_iam, audit_disabled, and the
# skip_final_snapshot rule that files under missing_lifecycle.
#
# Every line here is meant to be found. Its counterpart,
# insecure_config_clean.tf, is meant to be found by nothing — and the two are
# pinned by the same golden file, so loosening a pattern to catch more shows
# up as noise appearing in the clean half.

resource "aws_db_instance" "analytics" {
  identifier          = "analytics-prod"
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = "acme-reports"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_acl" "reports" {
  bucket = "acme-reports"
  acl    = "public-read"
}

# authenticated-read reads as a restriction and is not one: it means every
# AWS user anywhere, not every user of this account.
resource "aws_s3_bucket_acl" "internal" {
  bucket = "acme-internal"
  acl    = "authenticated-read"
}

resource "aws_instance" "bastion" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 500
  encrypted         = false
}

resource "aws_elasticache_replication_group" "cache" {
  replication_group_id       = "cache"
  transit_encryption_enabled = false
  at_rest_encryption_enabled = false
}

resource "aws_lb_listener" "legacy" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-3:1:loadbalancer/app/x/y"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2015-04"
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  s3_bucket_name = "trail-bucket"
  enable_logging = false
}

# The form no value matcher can see into: jsonencode over an object.
resource "aws_iam_role_policy" "admin" {
  name = "admin"
  role = "app"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# Public principal with no condition narrowing it.
resource "aws_iam_role" "anyone" {
  name = "anyone"

  assume_role_policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" }
    }]
  })
}

# Heredoc JSON reaches the same rule by the same path.
resource "aws_ecr_repository_policy" "app" {
  repository = "app"

  policy = <<-POLICY
    {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Principal": "*",
        "Action": "ecr:GetDownloadUrlForLayer"
      }]
    }
  POLICY
}

# The one policy form that IS declarative — real HCL blocks.
data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
