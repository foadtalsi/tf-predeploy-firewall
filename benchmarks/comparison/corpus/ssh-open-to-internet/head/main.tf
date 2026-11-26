resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = "vpc-0abc1234"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
