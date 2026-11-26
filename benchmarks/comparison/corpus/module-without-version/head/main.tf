module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = "main"
  cidr = "10.0.0.0/16"
}
