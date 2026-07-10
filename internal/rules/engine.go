// Package rules implements the risk-pattern detectors (categories a-d from
// the MVP spec) and the engine that runs them over a parsed diff.
package rules

import (
	"fmt"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/diff"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/ignore"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// RunOptions configures optional behaviour of the scan engine.
type RunOptions struct {
	// GlobalIgnore is a list of categories to suppress across all files.
	GlobalIgnore []report.Category
}

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

// Result is the outcome of a static-scan Run: the findings plus the set of
// attribute keys this PR's own .tf diff actually touched, per resource
// address. Plan-based rules (phase 2) use ChangedAttrs to distinguish an
// attribute the PR intentionally changed from one that drifted for some
// other reason.
type Result struct {
	Findings     []report.Finding
	ChangedAttrs map[string]map[ChangedAttrKey]bool // resource address -> changed attr keys
}

// Run parses every changed file and executes all rules against it,
// returning the combined findings after applying ignore directives.
// A parse error on one file is recorded as its own informational finding
// rather than aborting the whole scan.
func Run(files []diff.ChangedFile, aws *schema.AWS, ruleset []Rule, opts RunOptions) (Result, error) {
	var findings []report.Finding
	inlineByFile := make(map[string]map[int]map[report.Category]bool)
	changedAttrs := make(map[string]map[ChangedAttrKey]bool)

	for _, f := range files {
		// Collect inline ignore directives from the head revision source.
		inlineByFile[f.Path] = ignore.ParseComments(f.HeadContent)

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

		for _, head := range headResources {
			if base, existed := baseByAddr[head.Address()]; existed {
				changedAttrs[head.Address()] = changedAttrsForResource(head, base)
			}
		}
	}

	return Result{
		Findings:     ignore.Apply(findings, inlineByFile, opts.GlobalIgnore),
		ChangedAttrs: changedAttrs,
	}, nil
}
