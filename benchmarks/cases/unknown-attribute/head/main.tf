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

resource "digitalocean_droplet" "uncovered_provider" {
  name    = "acme-web"
  image   = "ubuntu-24-04-x64"
  made_up = true
}

resource "google_storage_bucket" "invented" {
  name     = "acme-gcs"
  location = "EU"
  made_up  = true
}

# Valid only under google-beta: multi_writer is not in the google schema, and
# the free tier carries no google-beta pack. The resource must be skipped, not
# judged against the google schema.
resource "google_compute_disk" "beta_arguments" {
  provider     = google-beta
  name         = "acme-shared"
  zone         = "europe-west1-b"
  multi_writer = true
}

# aws_security_group declares ingress as a set of objects; Terraform accepts the block
# syntax, so its fields are checked like a block's.
resource "aws_security_group" "nested_typo" {
  name   = "api"
  vpc_id = "vpc-0abc1234"

  ingress {
    from_port  = 443
    to_port    = 443
    protocol   = "tcp"
    cidr_block = "10.0.0.0/8"
  }
}

resource "aws_security_group" "nested_valid" {
  name   = "internal"
  vpc_id = "vpc-0abc1234"

  ingress {
    description     = "HTTPS from the private network"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks     = ["10.0.0.0/8"]
    security_groups = ["sg-0abc1234"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}
