variable "encrypt" {
  type    = bool
  default = true
}

# Positives: encryption at rest switched off.
resource "aws_db_instance" "unencrypted" {
  identifier        = "unencrypted"
  storage_encrypted = false
}

resource "aws_rds_cluster" "unencrypted" {
  cluster_identifier = "unencrypted"
  storage_encrypted  = false
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "eu-west-1a"
  size              = 100
  encrypted         = false
}

resource "aws_elasticache_replication_group" "unencrypted_at_rest" {
  replication_group_id       = "cache"
  description                = "cache"
  at_rest_encryption_enabled = false
}

resource "aws_instance" "unencrypted_root" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"

  root_block_device {
    encrypted = false
  }
}

# Positives: encryption in transit switched off.
resource "aws_elasticache_replication_group" "plaintext" {
  replication_group_id       = "plaintext"
  description                = "plaintext"
  transit_encryption_enabled = false
}

resource "aws_elasticache_replication_group" "plaintext_sessions" {
  replication_group_id       = "sessions"
  description                = "sessions"
  transit_encryption_enabled = false
}

resource "azurerm_storage_account" "plaintext" {
  name                       = "acmeplaintext"
  resource_group_name        = "storage"
  location                   = "westeurope"
  account_tier               = "Standard"
  account_replication_type   = "LRS"
  https_traffic_only_enabled = false
}

resource "azurerm_linux_web_app" "plaintext" {
  name                = "acme-web"
  resource_group_name = "web"
  location            = "westeurope"
  service_plan_id     = "/subscriptions/0/resourceGroups/web/providers/Microsoft.Web/serverFarms/plan"
  https_only          = false
}

resource "azurerm_windows_web_app" "plaintext" {
  name                = "acme-web-windows"
  resource_group_name = "web"
  location            = "westeurope"
  service_plan_id     = "/subscriptions/0/resourceGroups/web/providers/Microsoft.Web/serverFarms/plan"
  https_only          = false
}

# Positives: TLS policies that still accept TLS 1.0 or 1.1.
resource "aws_lb_listener" "tls_1_0_policy" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/1"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-1-2017-01"
}

resource "aws_lb_listener" "classic_default_policy" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/api/2"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
}

resource "aws_lb_listener" "tls13_with_tls10_floor" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/edge/3"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-0-2021-06"
}

resource "aws_api_gateway_domain_name" "tls_1_0" {
  domain_name     = "api.example.com"
  security_policy = "TLS_1_0"
}

resource "azurerm_storage_account" "tls_1_0" {
  name                     = "acmelegacytls"
  resource_group_name      = "storage"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_0"
}

resource "azurerm_mssql_server" "tls_1_1" {
  name                         = "acme-sql"
  resource_group_name          = "data"
  location                     = "westeurope"
  version                      = "12.0"
  minimum_tls_version          = "1.1"
}

# Near misses.
resource "aws_db_instance" "encrypted" {
  identifier        = "encrypted"
  storage_encrypted = true
}

resource "aws_ebs_volume" "from_default" {
  availability_zone = "eu-west-1a"
  size              = 100
  encrypted         = var.encrypt
}

resource "aws_efs_file_system" "encrypted" {
  creation_token = "shared"
  encrypted      = true
}

resource "azurerm_storage_account" "single_encryption" {
  name                              = "acmesingle"
  resource_group_name               = "storage"
  location                          = "westeurope"
  account_tier                      = "Standard"
  account_replication_type          = "LRS"
  infrastructure_encryption_enabled = false
}

resource "aws_elasticache_replication_group" "tls" {
  replication_group_id       = "tls"
  description                = "tls"
  transit_encryption_enabled = true
}

resource "azurerm_storage_account" "https_only" {
  name                       = "acmehttps"
  resource_group_name        = "storage"
  location                   = "westeurope"
  account_tier               = "Standard"
  account_replication_type   = "LRS"
  https_traffic_only_enabled = true
}

resource "azurerm_linux_web_app" "https_only" {
  name                = "acme-secure-web"
  resource_group_name = "web"
  location            = "westeurope"
  service_plan_id     = "/subscriptions/0/resourceGroups/web/providers/Microsoft.Web/serverFarms/plan"
  https_only          = true
}

resource "aws_lb_listener" "tls_1_2_policy" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/4"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
}

resource "aws_lb_listener" "tls13_policy" {
  load_balancer_arn = "arn:aws:elasticloadbalancing:eu-west-1:123456789012:loadbalancer/app/web/5"
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
}

resource "aws_api_gateway_domain_name" "tls_1_2" {
  domain_name     = "secure-api.example.com"
  security_policy = "TLS_1_2"
}

resource "azurerm_storage_account" "tls_1_2" {
  name                     = "acmemoderntls"
  resource_group_name      = "storage"
  location                 = "westeurope"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
}
