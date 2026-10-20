# Outbound traffic and default routes to 0.0.0.0/0 are how almost every VPC is built. They are
# not an exposure to the internet; the rules should not report them.
resource "aws_route" "default_via_internet_gateway" {
  route_table_id         = "rtb-0123456789abcdef0"
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = "igw-0123456789abcdef0"
}

resource "aws_route" "default_via_nat" {
  route_table_id         = "rtb-0123456789abcdef1"
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = "nat-0123456789abcdef0"
}

resource "aws_security_group_rule" "all_outbound" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  security_group_id = "sg-0123456789abcdef0"
  cidr_blocks       = ["0.0.0.0/0"]
}

resource "aws_vpc_security_group_egress_rule" "all_outbound" {
  security_group_id = "sg-0123456789abcdef0"
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_security_group" "app" {
  name = "app"

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_route_table" "public" {
  vpc_id = "vpc-0123456789abcdef0"

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = "igw-0123456789abcdef0"
  }
}
