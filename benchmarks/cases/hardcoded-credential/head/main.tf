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

# Near misses: more spellings of a value written to be replaced.
resource "aws_db_instance" "placeholder_angle_brackets" {
  identifier = "placeholder-angle-brackets"
  password   = "<YOUR_API_KEY>"
}

resource "aws_db_instance" "placeholder_your_key_here" {
  identifier = "placeholder-your-key-here"
  password   = "your-api-key-here"
}

resource "aws_db_instance" "placeholder_your_secret" {
  identifier = "placeholder-your-secret"
  password   = "YOUR_SECRET"
}

resource "aws_db_instance" "placeholder_insert_here" {
  identifier = "placeholder-insert-here"
  password   = "insert-token-here"
}

resource "aws_db_instance" "placeholder_x_run" {
  identifier = "placeholder-x-run"
  password   = "xxxxxxxxxxxxxxxx"
}

resource "aws_db_instance" "placeholder_masked" {
  identifier = "placeholder-masked"
  password   = "********"
}

resource "aws_db_instance" "placeholder_redacted" {
  identifier = "placeholder-redacted"
  password   = "REDACTED"
}

resource "aws_db_instance" "placeholder_redacted_brackets" {
  identifier = "placeholder-redacted-brackets"
  password   = "<redacted>"
}

resource "aws_db_instance" "placeholder_todo" {
  identifier = "placeholder-todo"
  password   = "TODO"
}

resource "aws_db_instance" "placeholder_fake" {
  identifier = "placeholder-fake"
  password   = "fake-password"
}

resource "aws_db_instance" "placeholder_sample" {
  identifier = "placeholder-sample"
  password   = "sample-key"
}

resource "aws_db_instance" "placeholder_change_it" {
  identifier = "placeholder-change-it"
  password   = "CHANGE_IT"
}

# Positives: weak passwords written in full are still credentials in source.
resource "aws_db_instance" "weak_password" {
  identifier = "weak-password"
  password   = "password123"
}

resource "aws_db_instance" "weak_default" {
  identifier = "weak-default"
  password   = "default-password"
}

resource "aws_db_instance" "word_secret" {
  identifier = "word-secret"
  password   = "secret"
}

# Static keys in a provider configuration are a credential leak like any other.
provider "aws" {
  alias      = "legacy"
  region     = "eu-west-3"
  access_key = "AKIA4QWX7N2LJ5RTP3KD"
  secret_key = "u7Fq2Lw9Zr4Xk8Pn1Vb6Hy3T"
}

# Keys read from variables are not.
provider "aws" {
  alias      = "from_variables"
  region     = "eu-west-3"
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}

# The name of a Secret Manager secret, which is how Cloud Run is told where to read one.
resource "google_cloud_run_v2_service" "secret_reference" {
  name     = "api"
  location = "europe-west1"

  template {
    containers {
      image = "europe-docker.pkg.dev/acme/api/api:1.4.2"

      env {
        name = "DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = "db-password"
            version = "latest"
          }
        }
      }
    }

    volumes {
      name = "config"
      secret {
        secret = "api-config"
      }
    }
  }
}

resource "google_cloudfunctions2_function" "secret_reference" {
  name     = "worker"
  location = "europe-west1"

  service_config {
    secret_environment_variables {
      key        = "API_KEY"
      project_id = "acme-prod"
      secret     = "worker-api-key"
      version    = "latest"
    }
  }
}

# An idempotency key, not a credential.
resource "aws_efs_file_system" "creation_token" {
  creation_token = "shared-data"
}
