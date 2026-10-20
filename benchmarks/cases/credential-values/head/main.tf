# Positives: credential formats in arguments whose names do not say "secret".
resource "aws_instance" "access_key_in_user_data" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data     = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
}

resource "aws_ssm_parameter" "access_key_value" {
  name  = "/ci/access-key-id"
  type  = "String"
  value = "AKIAI44QH8DHBEXAMPLE"
}

resource "aws_lambda_function" "access_key_description" {
  function_name = "exporter"
  role          = "arn:aws:iam::123456789012:role/exporter"
  description   = "uses AKIAIOSFODNN7EXAMPLE for the upload"
}

resource "aws_ssm_parameter" "secret_key_value" {
  name  = "/ci/secret-access-key"
  type  = "String"
  value = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_instance" "secret_key_in_user_data" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data     = "AWS_SECRET_ACCESS_KEY=je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
}

resource "aws_codebuild_project" "secret_key_description" {
  name         = "deploy"
  service_role = "arn:aws:iam::123456789012:role/codebuild"
  description  = "key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_ssm_parameter" "pem_rsa" {
  name  = "/tls/rsa"
  type  = "String"
  value = <<-PEM
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEAexampleexampleexample
    -----END RSA PRIVATE KEY-----
  PEM
}

resource "aws_ssm_parameter" "pem_ec" {
  name  = "/tls/ec"
  type  = "String"
  value = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIexample\n-----END EC PRIVATE KEY-----"
}

resource "aws_instance" "pem_openssh" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data     = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEexample\n-----END OPENSSH PRIVATE KEY-----"
}

resource "aws_lambda_function" "jwt_description" {
  function_name = "jwt-one"
  role          = "arn:aws:iam::123456789012:role/jwt"
  description   = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
}

resource "aws_ssm_parameter" "jwt_value" {
  name  = "/api/service-jwt"
  type  = "String"
  value = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJjaSIsImF1ZCI6ImFwaSJ9.c2lnbmF0dXJlLWJ5dGVzLWV4YW1wbGU"
}

resource "aws_codebuild_project" "jwt_description" {
  name         = "jwt-build"
  service_role = "arn:aws:iam::123456789012:role/codebuild"
  description  = "eyJ0eXAiOiJKV1QifQ.eyJyb2xlIjoiYWRtaW4ifQ.YWRtaW4tc2lnbmF0dXJl"
}

resource "aws_ssm_parameter" "github_classic" {
  name  = "/ci/github-classic"
  type  = "String"
  value = "ghp_aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
}

resource "aws_codebuild_project" "github_description" {
  name         = "github-build"
  service_role = "arn:aws:iam::123456789012:role/codebuild"
  description  = "ghp_Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8"
}

resource "aws_ssm_parameter" "github_fine_grained" {
  name  = "/ci/github-fine-grained"
  type  = "String"
  value = "github_pat_11ABCDEFG0aBcDeFgHiJkL_MnOpQrStUvWxYz0123456789AbCdEfGhIjKlMnOpQrStUvWxYz012345678"
}

resource "aws_ssm_parameter" "hex_value" {
  name  = "/ci/signing-key"
  type  = "String"
  value = "4f3c9a1be2d87065f1a3c5e7b9d2f4a6c8e0b2d4f6a8c1e3"
}

resource "aws_lambda_function" "hex_description" {
  function_name = "hex-one"
  role          = "arn:aws:iam::123456789012:role/hex"
  description   = "9b2e7f4a1c8d3e6f0a5b2c9d4e7f1a3b"
}

resource "aws_codebuild_project" "hex_description" {
  name         = "hex-build"
  service_role = "arn:aws:iam::123456789012:role/codebuild"
  description  = "e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"
}

resource "aws_ssm_parameter" "entropy_value" {
  name  = "/ci/webhook-signing"
  type  = "String"
  value = "x8Qz!Lm2#Vp9@Rt4$Wn7%Yb1^Hd6&Kf3*Gs5"
}

resource "aws_lambda_function" "entropy_description" {
  function_name = "entropy-one"
  role          = "arn:aws:iam::123456789012:role/entropy"
  description   = "Tq7Zp2Xw9Lk4Rm8Vn3Bc6Hd1Jf5Gs0Ae-_Yu7Io2"
}

resource "aws_codebuild_project" "entropy_description" {
  name         = "entropy-build"
  service_role = "arn:aws:iam::123456789012:role/codebuild"
  description  = "pZ3$kW9!mQ2@vX7#nB4%cR8^tY1&hJ6*gF5(dL0)"
}

# Near misses: values that look like a format at a glance and are not credentials.
resource "aws_lambda_function" "access_key_mentioned" {
  function_name = "rotation"
  role          = "arn:aws:iam::123456789012:role/rotation"
  description   = "rotates AKIA keys older than ninety days"
}

resource "aws_ssm_parameter" "access_key_lowercase" {
  name  = "/docs/example"
  type  = "String"
  value = "see akiaiosfodnn7example in the docs"
}

resource "aws_ssm_parameter" "access_key_reference" {
  name  = "/ci/access-key-id"
  type  = "String"
  value = aws_iam_access_key.ci.id
}

resource "aws_ssm_parameter" "secret_key_path" {
  name  = "/build/cache-path"
  type  = "String"
  value = "/usr/local/share/terraform/plugins/cache"
}

resource "aws_ssm_parameter" "secret_key_uppercase_run" {
  name  = "/build/marker"
  type  = "String"
  value = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
}

resource "aws_ssm_parameter" "secret_key_reference" {
  name  = "/ci/secret-access-key"
  type  = "String"
  value = aws_iam_access_key.ci.secret
}

resource "aws_ssm_parameter" "pem_public_key" {
  name  = "/tls/public"
  type  = "String"
  value = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIexample\n-----END PUBLIC KEY-----"
}

resource "aws_ssm_parameter" "pem_certificate" {
  name  = "/tls/certificate"
  type  = "String"
  value = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIexample\n-----END CERTIFICATE-----"
}

resource "aws_ssm_parameter" "pem_from_file" {
  name  = "/tls/key"
  type  = "SecureString"
  value = file("${path.module}/key.pem")
}

resource "aws_ssm_parameter" "jwt_prefix_only" {
  name  = "/api/header-prefix"
  type  = "String"
  value = "eyJhbGciOiJIUzI1NiJ9"
}

resource "aws_ssm_parameter" "jwt_in_sentence" {
  name  = "/docs/jwt"
  type  = "String"
  value = "tokens look like header.payload.signature"
}

resource "aws_ssm_parameter" "jwt_reference" {
  name  = "/api/service-jwt"
  type  = "SecureString"
  value = var.service_jwt
}

resource "aws_ssm_parameter" "github_short" {
  name  = "/ci/github-prefix"
  type  = "String"
  value = "ghp_short_example_value"
}

resource "aws_ssm_parameter" "github_oauth_prefix" {
  name  = "/ci/github-docs"
  type  = "String"
  value = "tokens start with ghp_ followed by 36 characters"
}

resource "aws_ssm_parameter" "github_reference" {
  name  = "/ci/github"
  type  = "SecureString"
  value = var.github_token
}

resource "aws_ssm_parameter" "hex_repeated" {
  name  = "/build/zeros"
  type  = "String"
  value = "00000000000000000000000000000000"
}

resource "aws_ssm_parameter" "hex_too_short" {
  name  = "/build/short-id"
  type  = "String"
  value = "4f3c9a1be2d87065f1a3c5e7b9d2f4a"
}

resource "aws_s3_object" "hex_etag" {
  bucket = "artifacts"
  key    = "release.zip"
  etag   = "d41d8cd98f00b204e9800998ecf8427e"
}

resource "aws_ssm_parameter" "entropy_sentence" {
  name  = "/docs/sentence"
  type  = "String"
  value = "The quick brown fox jumps over the lazy dog again"
}

resource "aws_ssm_parameter" "entropy_url" {
  name  = "/docs/url"
  type  = "String"
  value = "https://registry.terraform.io/providers/hashicorp/aws/latest/docs"
}

resource "aws_ssm_parameter" "entropy_arn" {
  name  = "/iam/role"
  type  = "String"
  value = "arn:aws:iam::123456789012:role/service-role/exporter-execution"
}

resource "aws_lambda_function" "hex_source_code_hash" {
  function_name    = "packaged"
  role             = "arn:aws:iam::123456789012:role/packaged"
  source_code_hash = "e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8"
}

resource "aws_ssm_parameter" "aws_access_key_extra_4" {
  name  = "/extra/aws_access_key_extra_4"
  type  = "String"
  value = "AKIAIOSFODNN7EXAMPLE"
}

resource "aws_ssm_parameter" "aws_access_key_extra_5" {
  name  = "/extra/aws_access_key_extra_5"
  type  = "String"
  value = "role=deploy key=AKIAI44QH8DHBEXAMPLE region=eu-west-1"
}

resource "aws_ssm_parameter" "aws_secret_key_extra_4" {
  name  = "/extra/aws_secret_key_extra_4"
  type  = "String"
  value = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
}

resource "aws_ssm_parameter" "aws_secret_key_extra_5" {
  name  = "/extra/aws_secret_key_extra_5"
  type  = "String"
  value = "secret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY end"
}

resource "aws_ssm_parameter" "pem_extra_4" {
  name  = "/extra/pem_extra_4"
  type  = "String"
  value = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiexample\n-----END PRIVATE KEY-----"
}

resource "aws_ssm_parameter" "pem_extra_5" {
  name  = "/extra/pem_extra_5"
  type  = "String"
  value = "key: -----BEGIN RSA PRIVATE KEY-----"
}

resource "aws_ssm_parameter" "jwt_extra_4" {
  name  = "/extra/jwt_extra_4"
  type  = "String"
  value = "eyJraWQiOiJrMSJ9.eyJzY29wZSI6InJlYWQifQ.c2lnLXR3by1leGFtcGxl"
}

resource "aws_ssm_parameter" "jwt_extra_5" {
  name  = "/extra/jwt_extra_5"
  type  = "String"
  value = "eyJhbGciOiJFUzI1NiJ9.eyJleHAiOjE3MDAwMDAwMDB9.ZXMyNTYtc2lnbmF0dXJl"
}

resource "aws_ssm_parameter" "github_token_extra_4" {
  name  = "/extra/github_token_extra_4"
  type  = "String"
  value = "ghp_Q1w2E3r4T5y6U7i8O9p0A1s2D3f4G5h6J7k8"
}

resource "aws_ssm_parameter" "github_token_extra_5" {
  name  = "/extra/github_token_extra_5"
  type  = "String"
  value = "ghp_m9N8b7V6c5X4z3L2k1J0h9G8f7D6s5A4p3O2"
}

resource "aws_ssm_parameter" "hex_extra_4" {
  name  = "/extra/hex_extra_4"
  type  = "String"
  value = "7d5e9c1a3b8f2e6d4c0a9b7e5f3d1c8a"
}

resource "aws_ssm_parameter" "hex_extra_5" {
  name  = "/extra/hex_extra_5"
  type  = "String"
  value = "a1f9e3c7b5d2048e6f1a3c5b7d9e2f40a8c6e4b2d0f9a7c5e3b1d8f6a4c2e0b9"
}

resource "aws_ssm_parameter" "entropy_extra_4" {
  name  = "/extra/entropy_extra_4"
  type  = "String"
  value = "Vb8#Nm2$Qw7!Er4%Ty1^Ui6&Op3*As9"
}

resource "aws_ssm_parameter" "entropy_extra_5" {
  name  = "/extra/entropy_extra_5"
  type  = "String"
  value = "Hk3Lp9Zx7Cv2Bn5Mq8Wf1Rt4Yg6Uj0Ik"
}
