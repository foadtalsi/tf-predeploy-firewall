# The required_providers block is described in this comment before it appears.
terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.0"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}
