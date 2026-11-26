module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=master"

  name = "main"
  cidr = "10.0.0.0/16"
}
