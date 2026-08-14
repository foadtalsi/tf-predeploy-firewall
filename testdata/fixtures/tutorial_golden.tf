# Corpus for the golden test that guards the tutorial-pattern detectors
# through their move out of Go and into the declarative rule pack. It is
# deliberately exhaustive rather than realistic: every branch, and every
# near-miss that must stay silent, appears exactly once.
#
# The strings below are the same ones already asserted in this package's unit
# tests. They are public documentation examples or random filler, never real
# credentials — the point of a corpus like this is that it can be committed.

# --- credential-bearing attribute names, by suffix -------------------------

resource "aws_db_instance" "primary" {
  identifier                  = "prod-orders-01"
  engine                      = "postgres"
  password                    = "changeme"
  administrator_login_password = "Hunter2Hunter2"
}

resource "azurerm_key_vault_secret" "app" {
  name         = "prod-app-secret"
  client_secret = "s0me-client-secret-value"
  api_key      = "abcdef123456789012345"
  auth_token   = "tok_abcdefghijklmnop"
}

resource "aws_dms_endpoint" "warehouse" {
  endpoint_id       = "prod-warehouse"
  connection_string = "Server=db;User Id=admin;Password=p4ssw0rd;"
}

# Credential-shaped names carrying values that are NOT credentials. None of
# these may fire: a bool is not a secret, and neither is an empty string.
resource "aws_rds_cluster" "managed" {
  cluster_identifier          = "prod-billing"
  manage_master_user_password = true
  password                    = ""
}

# Names that merely contain "key" are not credentials. public_key,
# partition_key and kms_key_id are ordinary configuration.
resource "aws_dynamodb_table" "events" {
  name          = "prod-events"
  hash_key      = "event_id"
  partition_key = "tenant_id"
  kms_key_id    = "arn:aws:kms:eu-west-1:123456789012:key/abcd"
}

# A credential reached through a variable default rather than written inline.
# The finding must still fire, must name the reference, and must NOT offer a
# one-click fix — the line here is already correct.
variable "db_password" {
  type    = string
  default = "resolved-through-a-default"
}

resource "aws_db_instance" "via_variable" {
  identifier = "prod-reporting"
  password   = var.db_password
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
  handler       = "index.handler"
  runtime       = "nodejs18.x"
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

# --- the near-misses that must stay silent ---------------------------------

# 41 characters of [a-z/] that the 40-char base64 class matches. This exact
# shape was reported as a leaked AWS secret key, at critical severity, when
# the scanner was run against this project's own Terraform. It is a path.
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

# Matches no known credential format at all. Randomness is the only signal
# left, so this must fire on entropy alone — at high rather than critical,
# because a statistical accusation is not a recognised credential shape.
resource "aws_ssm_parameter" "unknown_vendor_token" {
  name  = "/prod/vendor"
  type  = "SecureString"
  value = "Zk9#mQ2$vT7!xR4&pL8@wN3^cF6"
}

# High entropy, but public by design. An ARN must never be reported as a
# leaked secret; that failure mode is how a rule gets switched off.
resource "aws_ssm_parameter" "arn_value" {
  name  = "/prod/role"
  type  = "String"
  value = "arn:aws:iam::123456789012:role/Xk92MvQr7TzLp4Nw"
}

# A non-literal value cannot be pattern-matched and must never be guessed at.
resource "aws_ssm_parameter" "computed" {
  name  = "/prod/computed"
  type  = "SecureString"
  value = data.aws_secretsmanager_secret_version.current.secret_string
}

# --- open CIDR, top level and nested ---------------------------------------

resource "aws_security_group_rule" "ssh_from_anywhere" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
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
  identifier = "demo-cluster"
}

resource "aws_elasticache_cluster" "real" {
  cluster_id = "prod-sessions"
}
