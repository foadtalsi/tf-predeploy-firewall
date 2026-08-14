resource "aws_db_instance" "example" {
  identifier     = "example"
  engine         = "postgres"
  password       = "changeme"
  instance_class = "db.t3.medium"
}

resource "aws_security_group_rule" "open" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-abc123"
  cidr_blocks       = ["0.0.0.0/0"]
}
