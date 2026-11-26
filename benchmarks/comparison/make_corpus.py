"""Write the comparison corpus: one small Terraform repository per case.

Every case is a pull request. `base` is the repository before it, `head` after it.
A case is either a positive (the change carries one known problem, on one resource)
or a near miss (a change that looks risky but is correct, which no tool should flag
for that problem).
"""

import json
import shutil
import sys
from pathlib import Path

CORPUS = Path(sys.argv[1])

AWS_VERSIONS = """terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = "eu-west-3"
}
"""

AZURE_VERSIONS = """terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
  }
}

provider "azurerm" {
  features {}
}
"""

GOOGLE_VERSIONS = """terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.0"
    }
  }
}

provider "google" {
  project = "acme-prod"
  region  = "europe-west1"
}
"""

RDS = """resource "aws_db_instance" "primary" {{
  identifier          = "{identifier}"
  engine              = "postgres"
  engine_version      = "{engine_version}"
  instance_class      = "{instance_class}"
  allocated_storage   = 100
  db_name             = "{db_name}"
  username            = "appuser"
  password            = random_password.db.result
  storage_encrypted   = true
  deletion_protection = true
  skip_final_snapshot = false
}}

resource "random_password" "db" {{
  length  = 32
  special = true
}}
"""


def rds(**overrides):
    values = {
        "identifier": "prod-primary",
        "engine_version": "16.4",
        "instance_class": "db.r6g.xlarge",
        "db_name": "appdb",
    }
    values.update(overrides)
    return RDS.format(**values)


CASES = []


def case(
    name,
    category,
    kind,
    target,
    head,
    base=None,
    versions=AWS_VERSIONS,
    head_files=None,
    base_files=None,
    note="",
):
    CASES.append(
        {
            "name": name,
            "category": category,
            "kind": kind,
            "target": target,
            "head": head,
            "base": base,
            "versions": versions,
            "head_files": head_files or {},
            "base_files": base_files or {},
            "note": note,
        }
    )


# ---------------------------------------------------------------- destroy on apply
case(
    "rds-db-name-rename",
    "destroy",
    "positive",
    "aws_db_instance.primary",
    base=rds(),
    head=rds(db_name="app_production"),
    note="db_name is ForceNew: the instance is destroyed and recreated empty",
)
case(
    "dynamodb-hash-key-change",
    "destroy",
    "positive",
    "aws_dynamodb_table.sessions",
    base="""resource "aws_dynamodb_table" "sessions" {
  name         = "sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
""",
    head="""resource "aws_dynamodb_table" "sessions" {
  name         = "sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "session_id"

  attribute {
    name = "session_id"
    type = "S"
  }
}
""",
    note="hash_key is ForceNew: the table and its items are destroyed",
)
case(
    "s3-bucket-rename",
    "destroy",
    "positive",
    "aws_s3_bucket.uploads",
    base="""resource "aws_s3_bucket" "uploads" {
  bucket = "acme-uploads"
}
""",
    head="""resource "aws_s3_bucket" "uploads" {
  bucket = "acme-uploads-production"
}
""",
    note="bucket is ForceNew: the bucket is replaced",
)
case(
    "efs-enable-encryption",
    "destroy",
    "positive",
    "aws_efs_file_system.shared",
    base="""resource "aws_efs_file_system" "shared" {
  creation_token = "shared"
  encrypted      = false
}
""",
    head="""resource "aws_efs_file_system" "shared" {
  creation_token = "shared"
  encrypted      = true
}
""",
    note="encrypted is ForceNew on EFS: turning it on replaces the file system",
)
case(
    "azure-storage-account-rename",
    "destroy",
    "positive",
    "azurerm_storage_account.data",
    versions=AZURE_VERSIONS,
    base="""resource "azurerm_storage_account" "data" {
  name                     = "acmedata"
  resource_group_name      = "rg-data"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "GRS"
}
""",
    head="""resource "azurerm_storage_account" "data" {
  name                     = "acmedataprod"
  resource_group_name      = "rg-data"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "GRS"
}
""",
    note="name is ForceNew on a storage account",
)
case(
    "prevent-destroy-removed",
    "destroy",
    "positive",
    "aws_rds_cluster.main",
    base="""resource "aws_rds_cluster" "main" {
  cluster_identifier          = "main"
  engine                      = "aurora-postgresql"
  master_username             = "appuser"
  manage_master_user_password = true
  storage_encrypted           = true

  lifecycle {
    prevent_destroy = true
  }
}
""",
    head="""resource "aws_rds_cluster" "main" {
  cluster_identifier          = "main"
  engine                      = "aurora-postgresql"
  master_username             = "appuser"
  manage_master_user_password = true
  storage_encrypted           = true
}
""",
    note="the guard that stopped a destroy is removed in this change",
)
case(
    "rds-engine-version-bump",
    "destroy",
    "near-miss",
    "aws_db_instance.primary",
    base=rds(),
    head=rds(engine_version="16.6"),
    note="engine_version updates in place",
)
case(
    "rds-identifier-rename",
    "destroy",
    "near-miss",
    "aws_db_instance.primary",
    base=rds(),
    head=rds(identifier="prod-primary-eu"),
    note="identifier renames in place",
)
case(
    "rds-instance-class-change",
    "destroy",
    "near-miss",
    "aws_db_instance.primary",
    base=rds(),
    head=rds(instance_class="db.r6g.2xlarge"),
    note="instance_class modifies in place",
)
case(
    "dynamodb-billing-mode-change",
    "destroy",
    "near-miss",
    "aws_dynamodb_table.sessions",
    base="""resource "aws_dynamodb_table" "sessions" {
  name           = "sessions"
  billing_mode   = "PROVISIONED"
  read_capacity  = 5
  write_capacity = 5
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
""",
    head="""resource "aws_dynamodb_table" "sessions" {
  name         = "sessions"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}
""",
    note="billing_mode updates in place",
)

# ---------------------------------------------------------------- arguments that do not exist
case(
    "rds-hallucinated-deletion-protection",
    "invalid-argument",
    "positive",
    "aws_db_instance.primary",
    head=rds().replace("deletion_protection = true", "enable_deletion_protection = true"),
    note="the argument is deletion_protection",
)
case(
    "lambda-memory-typo",
    "invalid-argument",
    "positive",
    "aws_lambda_function.worker",
    head="""resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::123456789012:role/worker"
  runtime       = "python3.12"
  handler       = "main.handler"
  filename      = "worker.zip"
  memory        = 512
  timeout       = 30
}
""",
    note="the argument is memory_size",
)
case(
    "s3-hallucinated-versioning",
    "invalid-argument",
    "positive",
    "aws_s3_bucket.audit",
    head="""resource "aws_s3_bucket" "audit" {
  bucket             = "acme-audit"
  versioning_enabled = true
}
""",
    note="versioning is a separate resource, aws_s3_bucket_versioning",
)
case(
    "security-group-nested-typo",
    "invalid-argument",
    "positive",
    "aws_security_group.api",
    head="""resource "aws_security_group" "api" {
  name   = "api"
  vpc_id = "vpc-0abc1234"

  ingress {
    from_port  = 443
    to_port    = 443
    protocol   = "tcp"
    cidr_block = "10.0.0.0/8"
  }
}
""",
    note="the nested argument is cidr_blocks, a list",
)
case(
    "aks-removed-argument",
    "invalid-argument",
    "positive",
    "azurerm_kubernetes_cluster.main",
    versions=AZURE_VERSIONS,
    head="""resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-main"
  location            = "westeurope"
  resource_group_name = "rg-aks"
  dns_prefix          = "aksmain"

  default_node_pool {
    name                = "system"
    vm_size             = "Standard_D4s_v5"
    enable_auto_scaling = true
    min_count           = 2
    max_count           = 5
  }

  identity {
    type = "SystemAssigned"
  }
}
""",
    note="azurerm 4 renamed it auto_scaling_enabled; the old name is gone in 4 and 5",
)
case(
    "ec2-rare-valid-arguments",
    "invalid-argument",
    "near-miss",
    "aws_instance.batch",
    head="""resource "aws_instance" "batch" {
  ami         = "ami-0c55b159cbfafe1f0"
  hibernation = true

  launch_template {
    id      = "lt-0abc1234"
    version = "$Latest"
  }

  cpu_options {
    core_count       = 2
    threads_per_core = 1
  }

  metadata_options {
    http_tokens = "required"
  }

  root_block_device {
    encrypted = true
  }
}
""",
    note="every argument here is valid, if rarely used",
)
case(
    "lambda-valid-arguments",
    "invalid-argument",
    "near-miss",
    "aws_lambda_function.worker",
    head="""resource "aws_lambda_function" "worker" {
  function_name = "worker"
  role          = "arn:aws:iam::123456789012:role/worker"
  runtime       = "java21"
  handler       = "com.acme.Handler::handleRequest"
  filename      = "worker.zip"
  memory_size   = 1024
  timeout       = 30

  ephemeral_storage {
    size = 2048
  }

  snap_start {
    apply_on = "PublishedVersions"
  }
}
""",
    note="every argument here is valid",
)
case(
    "rds-valid-deletion-protection",
    "invalid-argument",
    "near-miss",
    "aws_db_instance.primary",
    head=rds(),
    note="the real argument, deletion_protection",
)

# ---------------------------------------------------------------- secrets
case(
    "rds-literal-password",
    "secret",
    "positive",
    "aws_db_instance.primary",
    head=rds().replace("random_password.db.result", '"Wq7!rTz2#Lp9vXc4"'),
    note="the password is written in the file",
)
case(
    "variable-default-password",
    "secret",
    "positive",
    "aws_db_instance.primary",
    head=rds().replace("random_password.db.result", "var.db_password")
    + """
variable "db_password" {
  type    = string
  default = "Vh3$kP8m!Qz2Ld7w"
}
""",
    note="the value comes from a variable default one indirection away",
)
case(
    "tfvars-api-key",
    "secret",
    "positive",
    "file:terraform.tfvars",
    head="""variable "datadog_api_key" {
  type      = string
  sensitive = true
}

resource "aws_ssm_parameter" "datadog" {
  name  = "/monitoring/datadog-api-key"
  type  = "SecureString"
  value = var.datadog_api_key
}
""",
    head_files={"terraform.tfvars": 'datadog_api_key = "9f3b2c7e81d64a0fb5e2c19d7a4f6083"\n'},
    note="a committed terraform.tfvars holds the key",
)
case(
    "provider-access-keys",
    "secret",
    "positive",
    "file:versions.tf",
    versions="""terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region     = "eu-west-3"
  access_key = "AKIA4QWX7N2LJ5RTP3KD"
  secret_key = "u7Fq2Lw9Zr4Xk8Pn1Vb6Hy3T"
}
""",
    head="""resource "aws_sqs_queue" "jobs" {
  name = "jobs"
}
""",
    note="static AWS keys in the provider block; the target file is versions.tf",
)
case(
    "module-input-github-token",
    "secret",
    "positive",
    "file:main.tf",
    head="""module "runner" {
  source  = "cloudposse/github-runners/aws"
  version = "0.1.0"

  github_token = "ghp_R4nD0mT0k3nV4lu3F0rT3st1ngX9q2Lk7Mw"
}
""",
    note="a GitHub token passed to a module",
)
case(
    "password-from-random-password",
    "secret",
    "near-miss",
    "aws_db_instance.primary",
    head=rds(),
    note="the password is generated, never written",
)
case(
    "password-from-secrets-manager",
    "secret",
    "near-miss",
    "aws_db_instance.primary",
    head=rds()
    .replace("random_password.db.result", "data.aws_secretsmanager_secret_version.db.secret_string")
    .replace(
        'resource "random_password" "db" {\n  length  = 32\n  special = true\n}\n',
        """data "aws_secretsmanager_secret_version" "db" {
  secret_id = "prod/db/password"
}
""",
    ),
    note="the password is read from Secrets Manager",
)
case(
    "sensitive-variable-no-default",
    "secret",
    "near-miss",
    "aws_db_instance.primary",
    head=rds().replace("random_password.db.result", "var.db_password")
    + """
variable "db_password" {
  type      = string
  sensitive = true
}
""",
    note="the value is supplied at apply time, outside the repository",
)
case(
    "rds-managed-master-password",
    "secret",
    "near-miss",
    "aws_rds_cluster.main",
    head="""resource "aws_rds_cluster" "main" {
  cluster_identifier          = "main"
  engine                      = "aurora-postgresql"
  master_username             = "appuser"
  manage_master_user_password = true
  storage_encrypted           = true
  deletion_protection         = true
}
""",
    note="RDS generates and stores the password",
)

# ---------------------------------------------------------------- public exposure
case(
    "ssh-open-to-internet",
    "exposure",
    "positive",
    "aws_security_group.bastion",
    head="""resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = "vpc-0abc1234"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
    note="port 22 open to the whole internet",
)
case(
    "rds-publicly-accessible",
    "exposure",
    "positive",
    "aws_db_instance.primary",
    head=rds().replace("  storage_encrypted", "  publicly_accessible = true\n  storage_encrypted"),
    note="the database gets a public endpoint",
)
case(
    "s3-public-read-acl",
    "exposure",
    "positive",
    "aws_s3_bucket_acl.assets",
    head="""resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
}

resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}
""",
    note="every object readable by anyone",
)
case(
    "s3-public-access-block-off",
    "exposure",
    "positive",
    "aws_s3_bucket_public_access_block.assets",
    head="""resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
}

resource "aws_s3_bucket_public_access_block" "assets" {
  bucket                  = aws_s3_bucket.assets.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}
""",
    note="the account-level safety net is switched off",
)
case(
    "https-from-private-range",
    "exposure",
    "near-miss",
    "aws_security_group.internal",
    head="""resource "aws_security_group" "internal" {
  name   = "internal"
  vpc_id = "vpc-0abc1234"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
""",
    note="HTTPS from the private network only",
)

# ---------------------------------------------------------------- IAM
case(
    "iam-admin-wildcard",
    "iam",
    "positive",
    "aws_iam_policy.ci",
    head="""resource "aws_iam_policy" "ci" {
  name = "ci"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
""",
    note="full admin on everything",
)
case(
    "iam-trust-anyone",
    "iam",
    "positive",
    "aws_iam_role.deployer",
    head="""resource "aws_iam_role" "deployer" {
  name = "deployer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "*" }
    }]
  })
}
""",
    note="any AWS account can assume the role",
)
case(
    "iam-scoped-read",
    "iam",
    "near-miss",
    "aws_iam_policy.reader",
    head="""resource "aws_iam_policy" "reader" {
  name = "reader"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::acme-reports/*"
    }]
  })
}
""",
    note="one action on one bucket",
)

# ---------------------------------------------------------------- encryption and data loss
case(
    "ebs-unencrypted",
    "encryption",
    "positive",
    "aws_ebs_volume.data",
    head="""resource "aws_ebs_volume" "data" {
  availability_zone = "eu-west-3a"
  size              = 200
  encrypted         = false
}
""",
    note="volume stored unencrypted",
)
case(
    "rds-storage-unencrypted",
    "encryption",
    "positive",
    "aws_db_instance.primary",
    head=rds().replace("storage_encrypted   = true", "storage_encrypted   = false"),
    note="database storage unencrypted",
)
case(
    "rds-skip-final-snapshot",
    "data-loss",
    "positive",
    "aws_db_instance.primary",
    head=rds().replace("skip_final_snapshot = false", "skip_final_snapshot = true"),
    note="a destroy leaves no snapshot behind",
)
case(
    "s3-force-destroy",
    "data-loss",
    "positive",
    "aws_s3_bucket.backups",
    head="""resource "aws_s3_bucket" "backups" {
  bucket        = "acme-backups"
  force_destroy = true
}
""",
    note="a destroy deletes every object, no questions asked",
)

# ---------------------------------------------------------------- supply chain
case(
    "module-without-version",
    "supply-chain",
    "positive",
    "module.vpc",
    head="""module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "main"
  cidr = "10.0.0.0/16"
}
""",
    note="the newest release is taken at every init",
)
case(
    "module-git-branch-ref",
    "supply-chain",
    "positive",
    "module.vpc",
    head="""module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=master"

  name = "main"
  cidr = "10.0.0.0/16"
}
""",
    note="a branch anyone with push access can move",
)
case(
    "module-git-commit-ref",
    "supply-chain",
    "near-miss",
    "module.vpc",
    head="""module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"

  name = "main"
  cidr = "10.0.0.0/16"
}
""",
    note="a full commit hash cannot move",
)

# ---------------------------------------------------------------- instance metadata
case(
    "imds-v1-allowed",
    "exposure",
    "positive",
    "aws_instance.web",
    head="""resource "aws_instance" "web" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.small"

  metadata_options {
    http_tokens = "optional"
  }

  root_block_device {
    encrypted = true
  }
}
""",
    note="IMDSv1 left on, the SSRF-to-credentials path",
)


# ---------------------------------------------------------------- Google Cloud
case(
    "gcp-sql-instance-rename",
    "destroy",
    "positive",
    "google_sql_database_instance.main",
    versions=GOOGLE_VERSIONS,
    base="""resource "google_sql_database_instance" "main" {
  name             = "prod-pg"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
  }
}
""",
    head="""resource "google_sql_database_instance" "main" {
  name             = "prod-pg-eu"
  database_version = "POSTGRES_16"
  region           = "europe-west1"

  settings {
    tier = "db-custom-2-7680"
  }
}
""",
    note="name is ForceNew on a Cloud SQL instance",
)
case(
    "gcp-gke-hallucinated-argument",
    "invalid-argument",
    "positive",
    "google_container_cluster.main",
    versions=GOOGLE_VERSIONS,
    head="""resource "google_container_cluster" "main" {
  name                  = "main"
  location              = "europe-west1"
  enable_autopilot_mode = true
}
""",
    note="the argument is enable_autopilot",
)
case(
    "gcp-firewall-ssh-open",
    "exposure",
    "positive",
    "google_compute_firewall.ssh",
    versions=GOOGLE_VERSIONS,
    head="""resource "google_compute_firewall" "ssh" {
  name    = "allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}
""",
    note="port 22 open to the whole internet",
)
case(
    "gcp-bucket-all-users",
    "exposure",
    "positive",
    "google_storage_bucket_iam_member.public",
    versions=GOOGLE_VERSIONS,
    head="""resource "google_storage_bucket" "reports" {
  name                        = "acme-reports"
  location                    = "EU"
  uniform_bucket_level_access = true
}

resource "google_storage_bucket_iam_member" "public" {
  bucket = google_storage_bucket.reports.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
""",
    note="every object readable by anyone",
)
case(
    "cloud-run-secret-reference",
    "secret",
    "near-miss",
    "google_cloud_run_v2_service.api",
    versions=GOOGLE_VERSIONS,
    head="""resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = "europe-west1"

  template {
    containers {
      image = "europe-docker.pkg.dev/acme-prod/api/api:1.4.2"

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
  }
}
""",
    note="the value is the name of a Secret Manager secret, which is the recommended way",
)
case(
    "efs-creation-token",
    "secret",
    "near-miss",
    "aws_efs_file_system.shared",
    head="""resource "aws_efs_file_system" "shared" {
  creation_token = "shared-data"
  encrypted      = true
}
""",
    note="creation_token is an idempotency key, not a credential",
)
case(
    "rds-cluster-default-key-encryption",
    "encryption",
    "near-miss",
    "aws_rds_cluster.main",
    head="""resource "aws_rds_cluster" "main" {
  cluster_identifier          = "main"
  engine                      = "aurora-postgresql"
  master_username             = "appuser"
  manage_master_user_password = true
  storage_encrypted           = true
  deletion_protection         = true
}
""",
    note="storage is encrypted with the AWS-managed key",
)


def write(directory, versions, main, files):
    directory.mkdir(parents=True)
    (directory / "versions.tf").write_text(versions)
    (directory / "main.tf").write_text(main)
    for name, content in files.items():
        (directory / name).write_text(content)


if CORPUS.exists():
    shutil.rmtree(CORPUS)
labels = []
for entry in CASES:
    case_dir = CORPUS / entry["name"]
    # Every case is a pull request. Cases without a base add their file in the PR.
    base_main = entry["base"] if entry["base"] is not None else ""
    if entry["base"] is not None:
        base_versions = entry["versions"]
    else:
        # The repository before the PR: the same provider, nothing else.
        base_versions = (
            entry["versions"]
            if entry["versions"] in (AZURE_VERSIONS, GOOGLE_VERSIONS)
            else AWS_VERSIONS
        )
    write(case_dir / "base", base_versions, base_main, entry["base_files"])
    write(case_dir / "head", entry["versions"], entry["head"], entry["head_files"])
    labels.append({key: entry[key] for key in ("name", "category", "kind", "target", "note")})
(CORPUS / "labels.json").write_text(json.dumps(labels, indent=2))
positives = sum(1 for label in labels if label["kind"] == "positive")
print(f"{len(labels)} cases: {positives} positives, {len(labels) - positives} near misses")
