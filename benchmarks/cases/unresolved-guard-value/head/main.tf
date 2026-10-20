variable "public" {}
variable "encrypted" {}
variable "skip_snapshot" {}
variable "tokens" {}
variable "trail_enabled" {}

variable "safe_default" {
  default = false
}

# Positives: guard settings the scanner cannot evaluate.
resource "aws_db_instance" "public_from_variable" {
  identifier          = "orders"
  publicly_accessible = var.public
}

resource "aws_ebs_volume" "encryption_from_variable" {
  availability_zone = "eu-west-1a"
  size              = 10
  encrypted         = var.encrypted
}

resource "aws_rds_cluster" "snapshot_from_variable" {
  cluster_identifier  = "ledger"
  skip_final_snapshot = var.skip_snapshot
}

resource "aws_instance" "tokens_from_variable" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = var.tokens
  }
}

resource "aws_cloudtrail" "logging_from_variable" {
  name           = "organization"
  s3_bucket_name = "acme-trail"
  enable_logging = var.trail_enabled
}

resource "aws_s3_bucket" "force_destroy_from_resource" {
  bucket        = "acme-data"
  force_destroy = aws_ssm_parameter.allow_destroy.value == "yes"
}

# Near misses: values the scanner can evaluate, and references that are not guard settings.
resource "aws_db_instance" "public_from_default" {
  identifier          = "billing"
  publicly_accessible = var.safe_default
}

resource "aws_db_instance" "credential_reference" {
  identifier = "reporting"
  password   = var.db_password
}

resource "aws_s3_bucket" "name_from_variable" {
  bucket = var.bucket_name
}

resource "aws_instance" "literal_tokens" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"
  }
}
