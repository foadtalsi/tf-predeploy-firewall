resource "aws_s3_bucket" "audit" {
  bucket             = "acme-audit"
  versioning_enabled = true
}
