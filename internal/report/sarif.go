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
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties"`
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
}

var severityToSarifLevel = map[Severity]string{
	SeverityLow:      "note",
	SeverityMedium:   "warning",
	SeverityHigh:     "error",
	SeverityCritical: "error",
}

// RenderSARIF serialises findings as a SARIF 2.1.0 JSON document suitable
// for upload to GitHub Code Scanning via actions/upload-sarif.
func RenderSARIF(findings []Finding) ([]byte, error) {
	results := make([]sarifResult, 0, len(findings))
	for _, f := range findings {
		results = append(results, sarifResult{
			RuleID:  string(f.Category),
			Level:   severityToSarifLevel[f.Severity],
			Message: sarifMessage{Text: f.Message},
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
				Version:        "0.1.0",
				InformationURI: "https://github.com/foadtalsi/tf-predeploy-firewall",
				Rules:          sarifRules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}
