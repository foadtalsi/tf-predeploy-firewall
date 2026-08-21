# Negative corpus: correct Terraform that the insecure_config rules must stay
# silent about.
#
# This half is the more valuable one. A detection rule is easy to write and
# easy to widen; what is hard is keeping it from firing on the code people
# actually ship, and a scanner that cries wolf gets switched off, taking its
# true positives with it. Every block below is a shape that a slightly looser
# pattern would catch by mistake, and the golden file pins the silence.
#
# Findings from OTHER categories are expected here — missing_lifecycle fires
# on the stateful types, and that is not what this fixture guards.

resource "aws_db_instance" "prod" {
  identifier          = "orders-prod"
  engine              = "postgres"
  publicly_accessible = false
  storage_encrypted   = true
  skip_final_snapshot = false
}

resource "aws_s3_bucket_public_access_block" "prod" {
  bucket                  = "acme-orders"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# A private canned ACL. "private" and "log-delivery-write" both contain
# neither of the public spellings and must not match.
resource "aws_s3_bucket_acl" "prod" {
  bucket = "acme-orders"
  acl    = "private"
}

resource "aws_instance" "worker" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "m6i.large"

  metadata_options {
    http_tokens = "required"
  }
}

# A current TLS policy. The version pattern has to match TLS-1-0 and TLS-1-1
# without also matching the 1-2 inside TLS13-1-2.
resource "aws_lb_listener" "https" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-3:1:loadbalancer/app/x/y"
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_cloudtrail" "main" {
  name           = "main"
  s3_bucket_name = "trail-bucket"
  enable_logging = true
}

# Scoped wildcards. "s3:*" is a service wildcard, not Action "*", and
# narrowing it further is ordinary least-privilege work rather than a finding.
resource "aws_iam_role_policy" "reader" {
  name = "reader"
  role = "app"

  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = "arn:aws:s3:::acme-orders/*"
    }]
  })
}

# Resource "*" with no wildcard action. Unavoidable for the many actions whose
# API takes no ARN, and the single largest false-positive source in this
# category if it were reported on its own.
resource "aws_iam_role_policy" "describe" {
  name = "describe"
  role = "app"

  policy = jsonencode({
    Statement = [{
      Effect   = "Allow"
      Action   = ["ec2:DescribeInstances", "s3:ListAllMyBuckets"]
      Resource = "*"
    }]
  })
}

# A public principal narrowed by a condition — the org-wide pattern, correct,
# and the reason the principal check is suppressed whenever a Condition
# appears anywhere in the document.
resource "aws_s3_bucket_policy" "org" {
  bucket = "acme-orders"

  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "arn:aws:s3:::acme-orders/*"
      Condition = {
        StringEquals = { "aws:PrincipalOrgID" = "o-acme123" }
      }
    }]
  })
}

# Attributes whose name contains "policy" but hold a name or an ARN, not a
# document. Reading one of these as a policy would produce a finding about
# text that is not a policy at all.
resource "aws_iam_role_policy_attachment" "app" {
  role       = "app"
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# A policy document naming specific actions and a specific principal.
data "aws_iam_policy_document" "scoped" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::acme-orders/*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/app"]
    }
  }
}
