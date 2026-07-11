package rules

import "testing"

func TestBareResourceAddress(t *testing.T) {
	cases := []struct{ in, want string }{
		{"aws_db_instance.prod", "aws_db_instance.prod"},
		{"module.vpc.aws_subnet.private", "aws_subnet.private"},
		{"module.vpc.module.subnets.aws_subnet.private", "aws_subnet.private"},
		{"aws_instance.web[0]", "aws_instance.web"},
		{`aws_instance.web["prod"]`, "aws_instance.web"},
		{"module.db.aws_db_instance.primary[0]", "aws_db_instance.primary"},
	}
	for _, c := range cases {
		got := bareResourceAddress(c.in)
		if got != c.want {
			t.Errorf("bareResourceAddress(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
