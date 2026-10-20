# Positives: ingress opened to the whole internet.
resource "aws_security_group_rule" "ssh_from_anywhere" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_vpc_security_group_ingress_rule" "rdp_from_anywhere" {
  security_group_id = "sg-0123456789abcdef0"
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_network_acl_rule" "all_inbound" {
  network_acl_id = "acl-0123456789abcdef0"
  rule_number    = 100
  egress         = false
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "database" {
  name = "database"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
  }
}

resource "aws_security_group" "admin" {
  name = "admin"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group_rule" "mysql_from_anywhere" {
  type              = "ingress"
  from_port         = 3306
  to_port           = 3306
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_security_group" "redis" {
  name = "redis"

  ingress {
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "postgres_from_anywhere" {
  security_group_id = "sg-0123456789abcdef0"
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "elasticsearch" {
  name = "search"

  ingress {
    from_port   = 9200
    to_port     = 9200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Near misses: private ranges, and references the scanner cannot judge.
resource "aws_security_group_rule" "ssh_from_office" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = ["203.0.113.0/24"]
}

resource "aws_vpc_security_group_ingress_rule" "https_from_vpc" {
  security_group_id = "sg-0123456789abcdef0"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "10.0.0.0/16"
}

resource "aws_security_group_rule" "from_variable" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = var.admin_cidrs
}

resource "aws_security_group" "internal" {
  name = "internal"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_security_group" "office" {
  name = "office"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["198.51.100.10/32"]
  }
}

resource "aws_security_group" "peered" {
  name = "peered"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = [var.peer_cidr]
  }
}
