# Positives: tutorial placeholders left in names and identifiers.
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket" "test_data" {
  bucket = "test-bucket-123"
}

resource "aws_db_instance" "demo" {
  identifier = "demo-cluster"
}

resource "aws_sqs_queue" "foo" {
  name = "foo"
}

resource "aws_iam_role" "sample" {
  name = "sample-role"
}

resource "aws_lambda_function" "my_app" {
  function_name = "orders"
  role          = "arn:aws:iam::123456789012:role/orders"
}

resource "aws_s3_bucket" "logs_with_prefix" {
  bucket_prefix = "tmp-"
}

# Near misses: deliberate names that merely contain a placeholder word.
resource "aws_s3_bucket" "testimonials" {
  bucket = "acme-testimonials"
}

resource "aws_db_instance" "examples_catalog" {
  identifier = "product-catalog"
}

resource "aws_sqs_queue" "latest_orders" {
  name = "contest-entries"
}

resource "aws_iam_role" "barcode_reader" {
  name = "barcode-reader"
}

resource "aws_s3_bucket" "temperature" {
  bucket = "temperature-readings"
}
