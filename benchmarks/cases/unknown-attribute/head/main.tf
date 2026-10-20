# Positives: arguments the provider schema does not declare for the type.
resource "aws_s3_bucket" "typo" {
  bucket = "acme-logs"
  acll   = "private"
}

resource "aws_instance" "invented" {
  ami                  = "ami-0abcdef1234567890"
  instance_type        = "t3.micro"
  auto_scaling_enabled = true
}

resource "aws_db_instance" "invented" {
  identifier          = "orders"
  backup_window_hours = 4
}

resource "aws_dynamodb_table" "invented" {
  name         = "orders"
  hash_key     = "id"
  billing_mode = "PAY_PER_REQUEST"
  encryption   = true

  attribute {
    name = "id"
    type = "S"
  }
}

resource "azurerm_storage_account" "invented" {
  name                     = "acmestorage"
  resource_group_name      = "storage"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  enable_versioning        = true
}

# Near misses: valid arguments, meta-arguments, and types the packs do not cover.
resource "aws_s3_bucket" "valid" {
  bucket        = "acme-valid"
  force_destroy = false
  tags          = { team = "platform" }
}

resource "aws_instance" "meta_arguments" {
  count         = 2
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  depends_on    = [aws_s3_bucket.valid]

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_instance" "recent_arguments" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  hibernation   = true

  launch_template {
    id = "lt-0123456789abcdef0"
  }
}

resource "google_storage_bucket" "uncovered_provider" {
  name     = "acme-gcs"
  location = "EU"
  made_up  = true
}
