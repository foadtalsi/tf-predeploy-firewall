resource "aws_s3_bucket" "logs" {
  bucket        = "acme-logs"
  force_destroy = true
