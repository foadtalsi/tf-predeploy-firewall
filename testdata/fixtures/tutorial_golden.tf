# Corpus for the golden test that guards the tutorial-pattern detectors.
# Exhaustive rather than realistic in what it exercises: every branch, and
# every near-miss that must stay silent, appears exactly once.
#
# It is nonetheless valid Terraform — `terraform validate` passes against the
# real AWS and Azure provider schemas. That is not tidiness. Every attribute
# below sits on a resource type that genuinely declares it, so the corpus
# cannot drift into testing against Terraform nobody could ever write, and
# the scanner's own unknown-attribute rule stays silent on it. A fixture its
# own tool flags is a fixture that has stopped describing reality.
#
# The strings here are public documentation examples or random filler, never
# real credentials — the point of a corpus like this is that it can be
# committed.

# --- credential-bearing attribute names, by suffix -------------------------

# The plain case.
resource "aws_db_instance" "primary" {
  identifier     = "prod-orders-01"
  engine         = "postgres"
  instance_class = "db.t3.medium"
  password       = "changeme"
}

# A provider-specific spelling. The name matcher is suffix-based precisely
# because every provider grows its own vocabulary; an exact-match list would
# always be one release behind.
resource "azurerm_mssql_server" "reporting" {
  name                         = "prod-reporting-sql"
  resource_group_name          = "prod-data"
  location                     = "westeurope"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "Hunter2Hunter2"
}

# Two credential suffixes on one resource.
resource "aws_pinpoint_baidu_channel" "notifications" {
  application_id = "prod-mobile"
  api_key        = "abcdef123456789012345"
  secret_key     = "fedcba098765432109876"
}

resource "aws_pinpoint_adm_channel" "amazon_devices" {
  application_id = "prod-mobile"
  client_id      = "prod-adm-client"
  client_secret  = "s0me-client-secret-value"
}

resource "aws_elasticache_replication_group" "sessions" {
  replication_group_id = "prod-sessions"
  description          = "session store"
  auth_token           = "tok-abcdefghijklmnopqrst"
}

resource "aws_workspaces_connection_alias" "desks" {
  connection_string = "Server=db;User Id=admin;Password=p4ssw0rd;"
}

resource "aws_acm_certificate" "internal" {
  private_key      = "internal-signing-key-material"
  certificate_body = "-----BEGIN CERTIFICATE-----"
}

# --- credential-shaped names that carry no credential ----------------------

# A bool is not a secret, and neither is an empty string.
# manage_master_user_password = true is the opposite of a leak: it hands the
# password to the provider so none is written here at all.
# Split across two clusters because the provider treats the pair as mutually
# exclusive — which is the point of the feature.
resource "aws_rds_cluster" "managed" {
  cluster_identifier          = "prod-billing"
  engine                      = "aurora-postgresql"
  manage_master_user_password = true
}

resource "aws_rds_cluster" "empty_password" {
  cluster_identifier = "prod-archive"
  engine             = "aurora-postgresql"
  master_password    = ""
}

# Names that merely contain "key" are ordinary configuration. This is why
# "key" is not a bare suffix in the matcher.
resource "aws_dynamodb_table" "events" {
  name      = "prod-events"
  hash_key  = "event_id"
  range_key = "occurred_at"
}

resource "aws_db_instance" "encrypted" {
  identifier     = "prod-ledger"
  engine         = "postgres"
  instance_class = "db.t3.medium"
  kms_key_id     = "arn:aws:kms:eu-west-1:123456789012:key/abcd"
}

# A credential reached through a variable default rather than written inline.
# The finding must still fire and must name the reference, but must NOT offer
# a one-click fix — the line here already reads `password = var.db_password`
# and is correct. The literal lives in the declaration.
variable "db_password" {
  type    = string
  default = "resolved-through-a-default"
}

resource "aws_db_instance" "via_variable" {
  identifier     = "prod-analytics"
  engine         = "postgres"
  instance_class = "db.t3.medium"
  password       = var.db_password
}

# --- credential-shaped values, regardless of attribute name ----------------

resource "aws_instance" "with_access_key" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  user_data     = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
}

resource "aws_instance" "with_secret_key" {
  ami           = "ami-0123456789abcdef0"
  instance_type = "t3.micro"
  user_data     = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_lambda_function" "with_jwt_value" {
  function_name = "prod-webhook"
  role          = "arn:aws:iam::123456789012:role/lambda"
  filename      = "webhook.zip"
  description   = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
}

resource "aws_ssm_parameter" "with_pem" {
  name  = "/prod/signing"
  type  = "SecureString"
  value = "-----BEGIN RSA PRIVATE KEY-----"
}

resource "aws_ssm_parameter" "with_forge_token" {
  name  = "/prod/ci"
  type  = "SecureString"
  value = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
}

resource "aws_ssm_parameter" "with_hex_digest" {
  name  = "/prod/digest"
  type  = "String"
  value = "9e107d9d372bb6826bd81d3542a419d6ab5f3c81"
}

# Matches no known credential format at all, so randomness is the only signal
# left. Fires at high rather than critical: a statistical accusation is not a
# recognised credential shape.
resource "aws_ssm_parameter" "unknown_vendor_token" {
  name  = "/prod/vendor"
  type  = "SecureString"
  value = "Zk9#mQ2$vT7!xR4&pL8@wN3^cF6"
}

# --- the near-misses that must stay silent ---------------------------------

# 41 characters of [a-z/] that the 40-char base64 class matches. This exact
# shape was reported as a leaked AWS secret key, at critical severity, when
# the scanner was first run against this project's own Terraform. It is a
# build command.
resource "null_resource" "build" {
  triggers = {
    always = "1"
  }

  provisioner "local-exec" {
    command = "go build -o infra/terraform/build/dashboard/bootstrap ./cmd/dashboard-lambda"
  }
}

resource "aws_s3_object" "long_path" {
  bucket = "prod-artifacts"
  key    = "modules/networking/environments/production/eu-west-one/vpc"
}

# Valid hex, 42 characters, and no entropy whatsoever. The "high-entropy hex
# string" label has to mean what it says.
resource "aws_ssm_parameter" "flat_hex" {
  name  = "/prod/padding"
  type  = "String"
  value = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

# Under the 16-character floor: too short to judge.
resource "aws_ssm_parameter" "short" {
  name  = "/prod/short"
  type  = "String"
  value = "abc123"
}

# High entropy, but public by design. An ARN reported as a leaked secret is
# how a rule gets switched off.
resource "aws_ssm_parameter" "arn_value" {
  name  = "/prod/role"
  type  = "String"
  value = "arn:aws:iam::123456789012:role/Xk92MvQr7TzLp4Nw"
}

# A non-literal value cannot be pattern-matched and must never be guessed at.
data "aws_secretsmanager_secret_version" "current" {
  secret_id = "prod/api"
}

resource "aws_ssm_parameter" "computed" {
  name  = "/prod/computed"
  type  = "SecureString"
  value = data.aws_secretsmanager_secret_version.current.secret_string
}

# --- open CIDR, top level and nested ---------------------------------------

resource "aws_security_group_rule" "ssh_from_anywhere" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-abc123"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group" "mixed" {
  name   = "prod-api-sg"
  vpc_id = "vpc-abc123"

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  # Narrow, and therefore silent.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# --- placeholder naming ----------------------------------------------------

resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket" "test_data" {
  bucket = "prod-analytics-eu-west-1"
}

resource "aws_db_instance" "deliberate" {
  identifier     = "demo-cluster"
  engine         = "postgres"
  instance_class = "db.t3.medium"
}

resource "aws_elasticache_cluster" "real" {
  cluster_id = "prod-sessions"
  engine     = "redis"
}
