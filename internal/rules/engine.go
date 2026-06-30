// Package rules implements the risk-pattern detectors (categories a-d from
// the MVP spec) and the engine that runs them over a parsed diff.
package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// FileInput is what each Rule sees for one changed .tf file.
type FileInput struct {
	Path string

	// HeadResources are the resource blocks as they exist after the change.
	HeadResources []*parser.Resource

	// BaseResources maps "type.name" -> resource as it existed before the
	// change, for files that existed at the base ref. Empty for new files.
	BaseResources map[string]*parser.Resource
}

// Rule is a single risk detector.
type Rule interface {
	Check(in FileInput, aws *schema.AWS) []report.Finding
}

// DefaultRules returns every built-in rule, in the order findings should
// be reported.
func DefaultRules() []Rule {
	return []Rule{
		UnknownAttributeRule{},
		TutorialPatternRule{},
		ForceNewChangeRule{},
		MissingLifecycleRule{},
	}
}

// Run parses every changed file and executes all rules against it,
// returning the combined findings. A parse error on one file is recorded
// as its own informational finding rather than aborting the whole scan.
func Run(files []diff.ChangedFile, aws *schema.AWS, ruleset []Rule) ([]report.Finding, error) {
	var findings []report.Finding

	for _, f := range files {
		headResources, err := parser.ParseFile(f.Path, f.HeadContent)
		if err != nil {
			findings = append(findings, report.Finding{
				File:     f.Path,
				Line:     1,
				Category: report.CategoryUnknownAttribute,
				Severity: report.SeverityMedium,
				Resource: "-",
				Message:  fmt.Sprintf("could not parse file as HCL: %v", err),
			})
			continue
		}

		baseByAddr := map[string]*parser.Resource{}
		if f.BaseContent != nil {
			baseResources, err := parser.ParseFile(f.Path, f.BaseContent)
			if err == nil {
				for _, r := range baseResources {
					baseByAddr[r.Address()] = r
				}
			}
		}

		in := FileInput{Path: f.Path, HeadResources: headResources, BaseResources: baseByAddr}
		for _, rule := range ruleset {
			findings = append(findings, rule.Check(in, aws)...)
		}
	}

	return findings, nil
}
