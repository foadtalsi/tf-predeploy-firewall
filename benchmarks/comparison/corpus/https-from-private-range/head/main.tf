resource "aws_security_group" "internal" {
  name   = "internal"
  vpc_id = "vpc-0abc1234"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
