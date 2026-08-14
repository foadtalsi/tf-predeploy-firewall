package parser

import "testing"

func TestTypeFromAddress(t *testing.T) {
	cases := []struct {
		addr     string
		wantType string
		wantData bool
		wantOK   bool
	}{
		{"aws_vpc.main", "aws_vpc", false, true},
		{"data.aws_ami.ubuntu", "aws_ami", true, true},

		// Plan addresses nest through modules, arbitrarily deep.
		{"module.rds.aws_db_instance.this", "aws_db_instance", false, true},
		{"module.a.module.b.aws_db_instance.this", "aws_db_instance", false, true},
		{"module.vpc.data.aws_availability_zones.available", "aws_availability_zones", true, true},

		// for_each / count keys hang off the name, never the type.
		{"aws_instance.web[0]", "aws_instance", false, true},
		{`module.envs["prod"].aws_vpc.main`, "aws_vpc", false, true},

		// A module call has no type of its own.
		{"module.rds", "", false, false},
		// The placeholder a whole-file finding carries.
		{"-", "", false, false},
		{"", "", false, false},
	}

	for _, c := range cases {
		gotType, gotData, gotOK := TypeFromAddress(c.addr)
		if gotType != c.wantType || gotData != c.wantData || gotOK != c.wantOK {
			t.Errorf("TypeFromAddress(%q) = (%q, %v, %v), want (%q, %v, %v)",
				c.addr, gotType, gotData, gotOK, c.wantType, c.wantData, c.wantOK)
		}
	}
}

// Address and TypeFromAddress have to agree, or a link points at the wrong
// page for exactly the blocks the parser produces.
func TestTypeFromAddress_RoundTripsWithAddress(t *testing.T) {
	for _, r := range []*Resource{
		{Kind: KindResource, Type: "aws_vpc", Name: "main"},
		{Kind: KindData, Type: "aws_ami", Name: "ubuntu"},
	} {
		gotType, gotData, ok := TypeFromAddress(r.Address())
		if !ok || gotType != r.Type || gotData != (r.Kind == KindData) {
			t.Errorf("%s: got (%q, %v, %v)", r.Address(), gotType, gotData, ok)
		}
	}

	if _, _, ok := TypeFromAddress((&Resource{Kind: KindModule, Name: "rds"}).Address()); ok {
		t.Error("a module call must not resolve to a resource type")
	}
}
