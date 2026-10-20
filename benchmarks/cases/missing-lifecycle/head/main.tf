# Positives: stateful resources without prevent_destroy = true.
resource "aws_db_instance" "orders" {
  identifier = "orders"
}

resource "aws_s3_bucket" "backups" {
  bucket = "acme-backups"
}

resource "aws_dynamodb_table" "sessions" {
  name     = "sessions"
  hash_key = "id"

  lifecycle {
    ignore_changes = [read_capacity]
  }
}

resource "aws_kms_key" "data" {
  description = "data key"

  lifecycle {
    prevent_destroy = false
  }
}

resource "azurerm_key_vault" "secrets" {
  name                = "acme-secrets"
  location            = "westeurope"
  resource_group_name = "security"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
}

# Near misses: protected stateful resources, and stateless ones.
resource "aws_rds_cluster" "protected" {
  cluster_identifier = "protected"

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_instance" "stateless" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}

resource "aws_security_group" "stateless" {
  name = "web"
}

resource "aws_efs_file_system" "protected" {
  creation_token = "shared"

  lifecycle {
    prevent_destroy = true
  }
}
