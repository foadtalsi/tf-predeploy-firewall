package schema

import (
	"strings"
	"testing"
)

// azurermPack is a minimal second-provider pack, as the control plane would
// serve it once Azure ships.
func azurermPack(t *testing.T) *KnowledgeBase {
	t.Helper()
	kb, errs := LoadWith(makePack(t, `{
		"format_version": 1,
		"id": "azurerm-full",
		"provider": "azurerm",
		"provider_version": "4.20.0",
		"resources": {
			"azurerm_mssql_server": {
				"top_level": ["name", "administrator_login"],
				"force_new_top_level": ["name"],
				"critical": true
			}
		}
	}`))
	if len(errs) > 0 {
		t.Fatalf("LoadWith: %v", errs)
	}
	return kb
}

// The whole point of the plumbing: packs for two providers coexist in one
// knowledge base, and neither provider's answers change because the other is
// loaded. Resource type prefixes are the namespace.
func TestMultiProvider_PacksCoexistWithoutInterfering(t *testing.T) {
	kb := azurermPack(t)

	// The Azure types answer.
	if s, ok := kb.ResourceSchema("azurerm_mssql_server"); !ok || s.TopLevel[0] != "name" {
		t.Errorf("azurerm type not resolved: %v %v", s, ok)
	}
	if !kb.IsCritical("azurerm_mssql_server") {
		t.Error("azurerm criticality lost")
	}
	if fn, ok := kb.ForceNew("azurerm_mssql_server"); !ok || fn.TopLevel[0] != "name" {
		t.Errorf("azurerm ForceNew lost: %v %v", fn, ok)
	}

	// And the AWS base pack still answers exactly as before.
	if _, ok := kb.ResourceSchema("aws_db_instance"); !ok {
		t.Error("loading an azurerm pack must not shadow the aws base pack")
	}
	if !kb.IsCritical("aws_db_instance") {
		t.Error("aws criticality lost after overlaying an unrelated provider")
	}
}

// The old Coverage had a single ProviderVersion field that whichever pack
// loaded last silently overwrote. Per-provider versions are the fix, and
// this pins it.
func TestMultiProvider_CoverageKeepsOneVersionPerProvider(t *testing.T) {
	c := azurermPack(t).Coverage()

	if got := c.VersionOf("azurerm"); got != "4.20.0" {
		t.Errorf("azurerm version = %q", got)
	}
	if got := c.VersionOf("aws"); got == "" || got == "4.20.0" {
		t.Errorf("aws version = %q — must be the aws pack's own, not the last loaded pack's", got)
	}
	if !c.Extended {
		t.Error("an overlaid pack must report extended coverage")
	}
	if c.VersionOf("google") != "" {
		t.Error("an uncovered provider must report no version")
	}
}

// Doc links must route by the pack a type resolved from: an azurerm finding
// linking into the AWS provider's docs would be worse than no link.
func TestMultiProvider_DocURLRoutesByProvider(t *testing.T) {
	kb := azurermPack(t)

	got := kb.DocURL("azurerm_mssql_server", false)
	want := "https://registry.terraform.io/providers/hashicorp/azurerm/4.20.0/docs/resources/mssql_server"
	if got != want {
		t.Errorf("DocURL = %q, want %q", got, want)
	}

	if aws := kb.DocURL("aws_db_instance", false); !strings.Contains(aws, "/aws/") {
		t.Errorf("aws DocURL broke after overlaying azurerm: %q", aws)
	}
}
