package main

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

func files(contents ...string) []diff.ChangedFile {
	out := make([]diff.ChangedFile, len(contents))
	for i, c := range contents {
		out[i] = diff.ChangedFile{Path: "f.tf", HeadContent: []byte(c)}
	}
	return out
}

func TestResolveProviders_DetectsFromBlockHeaders(t *testing.T) {
	got := resolveProviders("auto", files(`
resource "aws_db_instance" "prod" {}
data "aws_ami" "ubuntu" {}
resource "azurerm_mssql_server" "db" {}
`))
	if !reflect.DeepEqual(got, []string{"aws", "azurerm"}) {
		t.Errorf("got %v", got)
	}
}

// Only providers whose packs actually ship may be fetched. Listing one
// early made every scan of a GCP repo announce that coverage "falls back to
// the embedded pack" for a provider with no embedded pack — degraded
// coverage reported where there was none at all.
func TestResolveProviders_OnlyFetchesProvidersWithShippedPacks(t *testing.T) {
	got := resolveProviders("auto", files(`
resource "random_pet" "name" {}
resource "tls_private_key" "k" {}
resource "google_sql_database_instance" "db" {}
resource "aws_db_instance" "prod" {}
`))
	if !reflect.DeepEqual(got, []string{"aws"}) {
		t.Errorf("got %v, want [aws] — google ships no pack and must not be fetched", got)
	}
}

// A module-only diff needs no extended pack: the schema-driven rules skip
// module calls, so there is nothing an extended pack would add.
func TestResolveProviders_EmptyForModuleOnlyChanges(t *testing.T) {
	if got := resolveProviders("auto", files(`module "rds" { source = "./m" }`)); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// An explicit list is the user saying they know better — taken verbatim,
// unknown names included (the control plane answers 404 and the scan warns).
func TestResolveProviders_ExplicitListBypassesDetection(t *testing.T) {
	got := resolveProviders(" aws, oci ", files(`resource "azurerm_thing" "x" {}`))
	if !reflect.DeepEqual(got, []string{"aws", "oci"}) {
		t.Errorf("got %v", got)
	}
}

// A commented-out resource must not trigger a fetch. The regexp anchors on
// line start (with leading whitespace), which a `#` prefix breaks.
func TestResolveProviders_SkipsComments(t *testing.T) {
	if got := resolveProviders("auto", files("# resource \"aws_db_instance\" \"x\" {}\n")); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

// The silent half of the same defect: value-based rules fire on any
// provider, so an uncovered one produces a report that looks like it worked
// while the schema-driven rules sit inert. The scan has to say so.
func TestWarnUncoveredProviders(t *testing.T) {
	cov := schema.Coverage{Providers: []schema.ProviderCoverage{
		{Name: "aws", Version: "6.59.0"},
		{Name: "azurerm", Version: "4.81.0"},
	}}

	cases := map[string]struct {
		src  string
		want string // substring expected on stderr; "" means silence
	}{
		"uncovered provider is reported": {
			`resource "google_sql_database_instance" "db" {}`, "google"},
		"covered providers are silent": {
			"resource \"aws_vpc\" \"a\" {}\nresource \"azurerm_mssql_server\" \"b\" {}\n", ""},
		"schemaless providers are not a coverage gap": {
			"resource \"random_pet\" \"n\" {}\nresource \"tls_private_key\" \"k\" {}\nresource \"null_resource\" \"x\" {}\n", ""},
		"only the uncovered ones are named": {
			"resource \"aws_vpc\" \"a\" {}\nresource \"oci_core_vcn\" \"b\" {}\n", "oci"},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := captureStderr(t, func() { warnUncoveredProviders(files(c.src), cov) })
			if c.want == "" {
				if got != "" {
					t.Errorf("expected silence, got: %s", got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("expected %q in stderr, got: %s", c.want, got)
			}
			// The warning has to say what still ran, or it reads as "this
			// scan did nothing" and gets ignored.
			if !strings.Contains(got, "hardcoded credentials") {
				t.Errorf("warning must say which checks still applied, got: %s", got)
			}
		})
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	fn()
	w.Close()
	os.Stderr = orig

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
