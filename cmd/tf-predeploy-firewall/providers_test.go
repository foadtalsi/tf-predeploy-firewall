package main

import (
	"reflect"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
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

// random_pet, tls_private_key etc. are real providers the control plane has
// no packs for; detecting them would add a doomed fetch and its warning to
// every scan of a repo that uses them.
func TestResolveProviders_IgnoresProvidersWithoutPacks(t *testing.T) {
	got := resolveProviders("auto", files(`
resource "random_pet" "name" {}
resource "tls_private_key" "k" {}
resource "google_sql_database_instance" "db" {}
`))
	if !reflect.DeepEqual(got, []string{"google"}) {
		t.Errorf("got %v", got)
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
	if got := resolveProviders("auto", files("# resource \"google_thing\" \"x\" {}\n")); got != nil {
		t.Errorf("got %v, want nil", got)
	}
}
