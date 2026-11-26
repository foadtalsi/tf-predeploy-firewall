resource "aws_s3_bucket" "backups" {
  bucket        = "acme-backups"
  force_destroy = true
}
