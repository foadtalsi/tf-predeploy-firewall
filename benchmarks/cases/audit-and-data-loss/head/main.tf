variable "skip_snapshot" {
  type    = bool
  default = false
}

# Positives: audit trails switched off.
resource "aws_cloudtrail" "organization" {
  name           = "organization"
  s3_bucket_name = "acme-trail"
  enable_logging = false
}

resource "aws_cloudtrail" "management_events" {
  name           = "management"
  s3_bucket_name = "acme-trail"
  enable_logging = false
}

resource "aws_cloudtrail" "data_events" {
  name                  = "data-events"
  s3_bucket_name        = "acme-trail"
  is_multi_region_trail = true
  enable_logging        = false
}

resource "aws_cloudtrail" "security_account" {
  name           = "security"
  s3_bucket_name = "acme-security-trail"
  enable_logging = false
}

resource "aws_cloudtrail" "sandbox" {
  name           = "sandbox"
  s3_bucket_name = "acme-sandbox-trail"
  enable_logging = false
}

# Positives: deletion without a final snapshot.
resource "aws_db_instance" "no_final_snapshot" {
  identifier          = "orders"
  skip_final_snapshot = true
}

resource "aws_rds_cluster" "no_final_snapshot" {
  cluster_identifier  = "orders"
  skip_final_snapshot = true
}

resource "aws_docdb_cluster" "no_final_snapshot" {
  cluster_identifier  = "documents"
  skip_final_snapshot = true
}

resource "aws_neptune_cluster" "no_final_snapshot" {
  cluster_identifier  = "graph"
  skip_final_snapshot = true
}

resource "aws_redshift_cluster" "no_final_snapshot" {
  cluster_identifier  = "warehouse"
  node_type           = "ra3.xlplus"
  skip_final_snapshot = true
}

# Positives: buckets that delete their objects on destroy.
resource "aws_s3_bucket" "force_destroy_backups" {
  bucket        = "acme-backups"
  force_destroy = true
}

resource "aws_s3_bucket" "force_destroy_logs" {
  bucket        = "acme-logs"
  force_destroy = true
}

resource "aws_s3_bucket" "force_destroy_exports" {
  bucket        = "acme-exports"
  force_destroy = true
}

resource "aws_s3_bucket" "force_destroy_uploads" {
  bucket        = "acme-uploads"
  force_destroy = true
}

resource "aws_s3_bucket" "force_destroy_reports" {
  bucket        = "acme-reports"
  force_destroy = true
}

# Near misses.
resource "aws_cloudtrail" "enabled" {
  name           = "enabled"
  s3_bucket_name = "acme-trail"
  enable_logging = true
}

resource "aws_cloudtrail" "default" {
  name           = "default"
  s3_bucket_name = "acme-trail"
}

resource "aws_cloudwatch_event_rule" "disabled_schedule" {
  name  = "nightly"
  state = "DISABLED"
}

resource "aws_db_instance" "final_snapshot" {
  identifier                = "billing"
  skip_final_snapshot       = false
  final_snapshot_identifier = "billing-final"
}

resource "aws_rds_cluster" "snapshot_from_default" {
  cluster_identifier  = "ledger"
  skip_final_snapshot = var.skip_snapshot
}

resource "aws_db_instance" "snapshot_by_default" {
  identifier = "inventory"
}

resource "aws_s3_bucket" "kept_on_destroy" {
  bucket        = "acme-kept"
  force_destroy = false
}

resource "aws_s3_bucket" "default_destroy" {
  bucket = "acme-default"
}

resource "aws_ecr_repository" "force_delete_is_another_rule" {
  name         = "images"
  force_delete = true
}
