package schema

import (
	"fmt"
	"strings"
)

// registryNamespace maps a provider's short name to its Terraform Registry
// namespace. Unlisted providers fall back to hashicorp/<name>, which is right
// for the official ones and produces a link that 404s rather than a wrong one
// for anything else.
var registryNamespace = map[string]string{
	"aws":     "hashicorp",
	"azurerm": "hashicorp",
	"google":  "hashicorp",
}

// DocURL returns the Terraform Registry documentation page for a resource
// type, or "" when no loaded pack covers it.
//
// The URL pins the provider version the pack was generated from rather than
// pointing at "latest". A finding says an argument doesn't exist; the page
// backing that claim has to be the same provider release the scanner checked
// against, or the first thing a skeptical reader finds is a docs page that
// disagrees with the tool for reasons neither of them explains.
//
// Note that packs describe resource types only. A data source whose name has
// no resource counterpart — aws_availability_zones, aws_caller_identity —
// therefore gets no link, even though its documentation page exists. Guessing
// the URL from the type name would work most of the time, and the rest of the
// time would send someone to a 404 to check a claim; a missing link is the
// smaller failure.
func (a *KnowledgeBase) DocURL(rType string, dataSource bool) string {
	pack, ok := a.packFor(rType)
	if !ok {
		return ""
	}

	namespace, known := registryNamespace[pack.Provider]
	if !known {
		namespace = "hashicorp"
	}
	version := pack.ProviderVersion
	if version == "" {
		version = "latest"
	}

	// Registry doc slugs drop the provider prefix: aws_db_instance is
	// documented at .../docs/resources/db_instance.
	slug := strings.TrimPrefix(rType, pack.Provider+"_")
	section := "resources"
	if dataSource {
		section = "data-sources"
	}

	return fmt.Sprintf("https://registry.terraform.io/providers/%s/%s/%s/docs/%s/%s",
		namespace, pack.Provider, version, section, slug)
}

// packFor returns the pack a resource type was resolved from, so a doc link
// carries the provider version that pack actually describes — an overlaid
// extended pack and the embedded base pack can be built from different
// provider releases.
func (a *KnowledgeBase) packFor(rType string) (*loadedPack, bool) {
	for i := len(a.packs) - 1; i >= 0; i-- {
		if _, ok := a.packs[i].resource(rType); ok {
			return a.packs[i], true
		}
	}
	return nil, false
}
