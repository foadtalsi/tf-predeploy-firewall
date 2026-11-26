variable "datadog_api_key" {
  type      = string
  sensitive = true
}

resource "aws_ssm_parameter" "datadog" {
  name  = "/monitoring/datadog-api-key"
  type  = "SecureString"
  value = var.datadog_api_key
}
