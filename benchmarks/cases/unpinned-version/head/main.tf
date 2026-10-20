# Positives: module sources that follow whatever is published next.
module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
}

module "network" {
  source = "git::https://github.com/acme/terraform-network.git"
}

module "dns" {
  source = "git::https://github.com/acme/terraform-dns.git?ref=main"
}

# Near misses: pinned registry versions, tags, commits, and local paths.
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.0"
}

module "storage" {
  source = "git::https://github.com/acme/terraform-storage.git?ref=v1.4.2"
}

module "queues" {
  source = "git::https://github.com/acme/terraform-queues.git?ref=4f3c9a1be2d87065f1a3c5e7b9d2f4a6c8e0b2d4"
}

module "local" {
  source = "./modules/local"
}
