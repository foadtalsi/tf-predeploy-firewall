terraform {
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
