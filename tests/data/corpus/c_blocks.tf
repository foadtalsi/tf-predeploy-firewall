resource "aws_instance" "web" {
  ami = "ami-123"
  root_block_device {
    volume_size = 100
    encrypted   = true
  }
  ebs_block_device {
    device_name = "/dev/sdb"
  }
  dynamic "tag" {
    for_each = var.tags
    content {
      key = tag.key
    }
  }
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [ami]
  }
}
data "aws_ami" "found" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/*"]
  }
}
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
  cidr    = "10.0.0.0/16"
}
resource "aws_s3_bucket" "no_lifecycle" {
  bucket = "b"
}
resource "aws_db_instance" "pd_false" {
  identifier = "x"
  lifecycle {
    prevent_destroy = false
  }
}
resource "aws_db_instance" "pd_dynamic" {
  identifier = "y"
  lifecycle {
    prevent_destroy = var.protect
  }
}
