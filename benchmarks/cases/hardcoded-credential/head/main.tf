variable "db_password" {
  type    = string
  default = "hunter2-in-a-default"
}

variable "reporting_password" {
  type      = string
  sensitive = true
}

# Positives: a credential-named argument set to a literal, directly or through a default.
resource "aws_db_instance" "inline" {
  identifier = "orders"
  password   = "Sup3r-Secret-Value"
}

resource "aws_db_instance" "via_default" {
  identifier = "billing"
  password   = var.db_password
}

resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id = "sessions"
  description          = "session store"
  auth_token           = "abcdefghijklmnop1234"
}

resource "aws_dms_endpoint" "source" {
  endpoint_id   = "source"
  endpoint_type = "source"
  engine_name   = "postgres"
  password      = "dms-replication-pass"
}

resource "azurerm_kubernetes_cluster" "platform" {
  name                = "platform"
  location            = "westeurope"
  resource_group_name = "platform"
  dns_prefix          = "platform"

  service_principal {
    client_id     = "00000000-0000-0000-0000-000000000000"
    client_secret = "client-secret-in-source"
  }
}

# Near misses: credential-named arguments that are not credentials in source.
resource "aws_db_instance" "from_variable" {
  identifier = "reporting"
  password   = var.reporting_password
}

resource "aws_rds_cluster" "managed" {
  cluster_identifier          = "managed"
  manage_master_user_password = true
}

resource "aws_db_instance" "generated" {
  identifier = "generated"
  password   = random_password.database.result
}

resource "aws_iam_user_login_profile" "operator" {
  user            = "operator"
  password_length = 24
}

# Near misses reported from real repositories: placeholders, not credentials.
resource "aws_db_instance" "replace_me" {
  identifier = "staging"
  password   = "REPLACE ME"
}

resource "cloudflare_api_token" "dummy" {
  name      = "ci"
  api_token = "dummy-cloudflare-tokens-0123456789abcdef"
}

resource "azurerm_mssql_server" "change_me" {
  name                         = "acme-sql"
  administrator_login_password = "changeme"
}
