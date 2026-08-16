package report

import "encoding/json"

// SARIF 2.1.0 structures (minimal subset needed for GitHub Code Scanning).
// Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  *sarifMessage       `json:"fullDescription,omitempty"`
	Help             *sarifHelp          `json:"help,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
}

// sarifHelp carries the long-form explanation of a rule. GitHub Code
// Scanning renders Markdown on the alert page and falls back to Text
// elsewhere, so both are populated from the same source.
type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags"`
	Severity string   `json:"severity"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`

	// Properties carries the per-result provider documentation link. It can't
	// go on the rule: a rule is one category across every resource type,
	// while the useful link is to the one type this result is about.
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

var sarifRules = []sarifRule{
	{
		ID:               string(CategoryUnknownAttribute),
		Name:             "UnknownAttribute",
		ShortDescription: sarifMessage{Text: "Unknown or hallucinated Terraform attribute"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "ai-hallucination"}, Severity: "error"},
	},
	{
		ID:               string(CategoryUnpinnedVersion),
		Name:             "UnpinnedVersion",
		ShortDescription: sarifMessage{Text: "Module source or provider requirement with no version pin"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "supply-chain", "reproducibility"}, Severity: "warning"},
	},
	{
		ID:               string(CategoryTutorialPattern),
		Name:             "TutorialPattern",
		ShortDescription: sarifMessage{Text: "Tutorial copy-paste pattern (hardcoded credential, open CIDR, generic name)"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "security", "secrets"}, Severity: "error"},
	},
	{
		ID:               string(CategoryForceNewChange),
		Name:             "ForceNewChange",
		ShortDescription: sarifMessage{Text: "Change to a ForceNew attribute will destroy and recreate the resource"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "destructive-change"}, Severity: "warning"},
	},
	{
		ID:               string(CategoryMissingLifecycle),
		Name:             "MissingLifecycle",
		ShortDescription: sarifMessage{Text: "Stateful resource missing lifecycle { prevent_destroy = true }"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "data-safety"}, Severity: "warning"},
	},
	// The insecure_config group. Severity here is SARIF's own notion, not the
	// scanner's: it decides how GitHub Code Scanning ranks the alert, and
	// "error" is what puts an alert above the fold in a dashboard somebody
	// checks weekly. These four earn it because every one of them reports a
	// value that was written down rather than a default left alone.
	{
		ID:               string(CategoryPublicExposure),
		Name:             "PublicExposure",
		ShortDescription: sarifMessage{Text: "A resource or its data explicitly placed on the public internet"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "security", "exposure"}, Severity: "error"},
	},
	{
		ID:               string(CategoryEncryptionDisabled),
		Name:             "EncryptionDisabled",
		ShortDescription: sarifMessage{Text: "Encryption at rest or in transit switched off, or a TLS policy permitting TLS 1.0/1.1"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "security", "encryption"}, Severity: "error"},
	},
	{
		ID:               string(CategoryPermissiveIAM),
		Name:             "PermissiveIAM",
		ShortDescription: sarifMessage{Text: "IAM policy granting every action, or granting to every principal with no condition"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "security", "iam", "least-privilege"}, Severity: "error"},
	},
	{
		ID:               string(CategoryAuditDisabled),
		Name:             "AuditDisabled",
		ShortDescription: sarifMessage{Text: "An audit trail or diagnostic setting explicitly disabled"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "security", "audit", "compliance"}, Severity: "warning"},
	},
	{
		ID:               string(CategoryConfirmedReplace),
		Name:             "ConfirmedReplace",
		ShortDescription: sarifMessage{Text: "terraform plan confirms a destroy or destroy+recreate on a stateful resource"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "plan", "data-safety"}, Severity: "error"},
	},
	{
		ID:               string(CategoryUnexpectedDrift),
		Name:             "UnexpectedDrift",
		ShortDescription: sarifMessage{Text: "terraform plan changes a sensitive attribute not touched by this PR's .tf diff"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "plan", "drift"}, Severity: "warning"},
	},
	{
		ID:               string(CategoryLargeBlastRadius),
		Name:             "LargeBlastRadius",
		ShortDescription: sarifMessage{Text: "terraform plan destroys/replaces an unusually large number of resources"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "plan", "blast-radius"}, Severity: "warning"},
	},
	{
		ID:               string(CategoryCostImpact),
		Name:             "CostImpact",
		ShortDescription: sarifMessage{Text: "terraform plan increases the estimated monthly AWS bill by more than the configured threshold"},
		Properties:       sarifRuleProperties{Tags: []string{"terraform", "plan", "finops", "cost"}, Severity: "warning"},
	},
}

// describedRules is sarifRules with each entry's help text, full description
// and documentation link filled in from the rule pack.
//
// Kept as a derivation rather than written into the literals above so the two
// can't drift: a category added to one and forgotten in the other shows up as
// a rule with no explanation, which the test asserts against.
func describedRules() []sarifRule {
	out := make([]sarifRule, len(sarifRules))
	copy(out, sarifRules)

	for i, r := range out {
		c := Category(r.ID)
		out[i].HelpURI = ruleHelpURI(c)
		if h, ok := lookupRuleHelp(c); ok {
			out[i].FullDescription = &sarifMessage{Text: h.fullDescription}
			out[i].Help = &sarifHelp{Text: h.fullDescription, Markdown: h.markdown}
		}
	}
	return out
}

var severityToSarifLevel = map[Severity]string{
	SeverityLow:      "note",
	SeverityMedium:   "warning",
	SeverityHigh:     "error",
	SeverityCritical: "error",
}

// ToolVersion appears as the driver version in SARIF output. main stamps it
// from the release ldflags; "dev" means a from-source build. A package var
// rather than a parameter because exactly one caller will ever set it and
// every render site would otherwise thread it through untouched.
var ToolVersion = "dev"

// RenderSARIF serialises findings as a SARIF 2.1.0 JSON document suitable
// for upload to GitHub Code Scanning via actions/upload-sarif.
func RenderSARIF(findings []Finding) ([]byte, error) {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		var props map[string]string
		if f.DocURL != "" {
			props = map[string]string{"providerDocs": f.DocURL, "resource": f.Resource}
		}
		results = append(results, sarifResult{
			RuleID:     string(f.Category),
			Level:      severityToSarifLevel[f.Severity],
			Message:    sarifMessage{Text: f.Message},
			Properties: props,
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{
						URI:       f.File,
						URIBaseID: "%SRCROOT%",
					},
					Region: sarifRegion{StartLine: f.Line},
				},
			}},
		})
	}

	log := sarifLog{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "tf-predeploy-firewall",
				Version:        ToolVersion,
				InformationURI: "https://github.com/foadtalsi/tf-predeploy-firewall",
				Rules:          describedRules(),
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}
