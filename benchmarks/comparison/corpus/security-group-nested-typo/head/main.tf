resource "aws_security_group" "api" {
  name   = "api"
  vpc_id = "vpc-0abc1234"

  ingress {
    from_port  = 443
    to_port    = 443
    protocol   = "tcp"
    cidr_block = "10.0.0.0/8"
  }
}
