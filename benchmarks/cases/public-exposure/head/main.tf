variable "db_public" {
  type    = bool
  default = false
}

# Positives: data stores given a public address.
resource "aws_db_instance" "public" {
  identifier          = "public"
  publicly_accessible = true
}

resource "aws_db_instance" "public_reporting" {
  identifier          = "reporting"
  publicly_accessible = true
}

resource "aws_rds_cluster_instance" "public" {
  identifier          = "public-1"
  cluster_identifier  = "orders"
  instance_class      = "db.r6g.large"
  engine              = "aurora-postgresql"
  publicly_accessible = true
}

resource "aws_redshift_cluster" "public" {
  cluster_identifier  = "warehouse"
  node_type           = "ra3.xlplus"
  publicly_accessible = true
}

resource "aws_dms_replication_instance" "public" {
  replication_instance_id    = "migration"
  replication_instance_class = "dms.t3.medium"
  publicly_accessible        = true
}

# Positives: canned ACLs that grant outside the account.
resource "aws_s3_bucket_acl" "public_read" {
  bucket = "acme-site"
  acl    = "public-read"
}

resource "aws_s3_bucket_acl" "public_read_write" {
  bucket = "acme-uploads"
  acl    = "public-read-write"
}

resource "aws_s3_bucket_acl" "authenticated_read" {
  bucket = "acme-shared"
  acl    = "authenticated-read"
}

resource "aws_s3_bucket" "legacy_public" {
  bucket = "acme-legacy"
  acl    = "public-read"
}

resource "aws_s3_object" "public_object" {
  bucket = "acme-site"
  key    = "index.html"
  acl    = "public-read"
}

# Positives: the public access block switched off.
resource "aws_s3_bucket_public_access_block" "all_off" {
  bucket                  = "acme-site"
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_public_access_block" "policy_off" {
  bucket                  = "acme-uploads"
  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Positives: instance metadata reachable without a session token.
resource "aws_instance" "imds_v1" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_launch_template" "imds_v1" {
  name = "workers"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }
}

resource "aws_instance" "imds_v1_bastion" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_launch_template" "imds_v1_batch" {
  name = "batch"

  metadata_options {
    http_tokens = "optional"
  }
}

resource "aws_instance" "imds_v1_legacy" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_put_response_hop_limit = 2
    http_tokens                 = "optional"
  }
}

# Near misses.
resource "aws_db_instance" "private" {
  identifier          = "private"
  publicly_accessible = false
}

resource "aws_db_instance" "from_default" {
  identifier          = "from-default"
  publicly_accessible = var.db_public
}

resource "aws_redshift_cluster" "private" {
  cluster_identifier = "private-warehouse"
  node_type          = "ra3.xlplus"
}

resource "aws_s3_bucket_acl" "private" {
  bucket = "acme-private"
  acl    = "private"
}

resource "aws_s3_bucket_acl" "log_delivery" {
  bucket = "acme-logs"
  acl    = "log-delivery-write"
}

resource "aws_s3_object" "owner_full_control" {
  bucket = "acme-shared"
  key    = "report.csv"
  acl    = "bucket-owner-full-control"
}

resource "aws_s3_bucket_public_access_block" "all_on" {
  bucket                  = "acme-private"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "defaults" {
  bucket = "acme-defaults"
}

resource "aws_s3_bucket_public_access_block" "from_variable" {
  bucket              = "acme-variable"
  block_public_policy = var.block_policy
}

resource "aws_instance" "imds_v2" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"
  }
}

resource "aws_launch_template" "imds_disabled" {
  name = "isolated"

  metadata_options {
    http_endpoint = "disabled"
  }
}

resource "aws_instance" "no_metadata_options" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}
