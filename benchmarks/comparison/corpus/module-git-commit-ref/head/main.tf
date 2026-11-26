module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"

  name = "main"
  cidr = "10.0.0.0/16"
}
