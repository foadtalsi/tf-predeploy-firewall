package schema

import (
	"strings"
	"testing"
)

func TestDocURL_LinksTheResourcePage(t *testing.T) {
	aws, err := Load()
	if err != nil {
		t.Fatal(err)
	}

	got := aws.DocURL("aws_db_instance", false)
	if !strings.HasSuffix(got, "/docs/resources/db_instance") {
		t.Errorf("DocURL = %q — the registry drops the provider prefix from the slug", got)
	}
	if !strings.HasPrefix(got, "https://registry.terraform.io/providers/hashicorp/aws/") {
		t.Errorf("DocURL = %q", got)
	}
}

func TestDocURL_LinksTheDataSourcePage(t *testing.T) {
	aws, _ := Load()
	got := aws.DocURL("aws_db_instance", true)
	if !strings.Contains(got, "/docs/data-sources/") {
		t.Errorf("DocURL = %q, want the data-sources section", got)
	}
}

// Packs describe resource types only, so a data source with no resource of
// the same name gets no link. Asserted rather than left implicit: it is a
// real limitation, and the alternative — guessing the URL — would sometimes
// send someone to a 404 to verify a finding.
func TestDocURL_NoLinkForADataSourceOnlyType(t *testing.T) {
	aws, _ := Load()
	if got := aws.DocURL("aws_caller_identity", true); got != "" {
		t.Errorf("DocURL = %q, want empty — no pack covers this type", got)
	}
}

// A finding claims an argument doesn't exist. The page backing that claim has
// to describe the same provider release the claim was checked against.
func TestDocURL_PinsThePackProviderVersion(t *testing.T) {
	aws, _ := Load()
	version := aws.Coverage().VersionOf("aws")
	if version == "" {
		t.Skip("base pack declares no provider version")
	}
	if got := aws.DocURL("aws_db_instance", false); !strings.Contains(got, "/"+version+"/") {
		t.Errorf("DocURL = %q, want the pinned version %s", got, version)
	}
}

// A link to a page that may not exist is worse than no link: it invites
// someone to check, and wastes the trip.
func TestDocURL_EmptyForAnUncoveredType(t *testing.T) {
	aws, _ := Load()
	if got := aws.DocURL("aws_totally_made_up_type", false); got != "" {
		t.Errorf("DocURL = %q, want empty for a type no pack covers", got)
	}
}
