resource "aws_db_instance" "example" {
  identifier = "example"
  engine     = "postgres"
  password   = "changeme"
}

resource "aws_security_group_rule" "open" {
  type        = "ingress"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}
