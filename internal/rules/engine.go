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

	// RepoDir is the checkout root. When set, each scanned file's whole
	// directory is read to build a scope for resolving `var.x` and `local.y`
	// — Terraform scopes those per directory, not per file, so a local
	// declared in locals.tf has to be visible when scanning rds.tf.
	//
	// Leaving it empty disables reference resolution entirely; every rule
	// then behaves exactly as it did before, skipping non-literal values.
	RepoDir string
}

// FileInput is what each Rule sees for one changed .tf file.
type FileInput struct {
	Path string

	// HeadResources are the resource blocks as they exist after the change.
	HeadResources []*parser.Resource

	// HeadSource is the raw file content the head resources were parsed
	// from. Rules use it to build report.Fix values, which have to reproduce
	// existing lines byte-for-byte. Optional: with it empty, rules simply
	// emit no one-click fixes, which is why unit tests that construct a
	// FileInput by hand don't have to supply it.
	HeadSource []byte

	// BaseResources maps "type.name" -> resource as it existed before the
	// change, for files that existed at the base ref. Empty for new files.
	BaseResources map[string]*parser.Resource
}

// Rule is a single risk detector.
type Rule interface {
	Check(in FileInput, kb *schema.KnowledgeBase) []report.Finding
}

// DefaultRules returns the built-in rule set, in pack order.
//
// The rules themselves are declarations in internal/ruledef/rules.yaml, not
// Go: what each one looks for, how its finding is worded, and what the
// documentation says are all data. This function only resolves those
// declarations into runnable form.
func DefaultRules(opts Options) []Rule {
	ruleset, err := FromPack(BuiltinPack(), opts)
	if err != nil {
		// FromPack only fails on a malformed pack, and the built-in pack is
		// embedded in this binary — so this is a broken build, not a bad
		// input, and carrying on would mean scanning with rules missing.
		panic("tf-predeploy-firewall: " + err.Error())
	}
	return ruleset
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
func Run(files []diff.ChangedFile, kb *schema.KnowledgeBase, ruleset []Rule, opts RunOptions) (Result, error) {
	var findings []report.Finding
	inlineByFile := make(map[string]map[int]map[report.Category]bool)
	changedAttrs := make(map[string]map[ChangedAttrKey]bool)

	scopes := newScopeCache(opts.RepoDir)

	for _, f := range files {
		// Collect inline ignore directives from the head revision source.
		inlineByFile[f.Path] = ignore.ParseComments(f.HeadContent)

		// The scope is built from the file's own directory, with this file's
		// head content overriding whatever is on disk — on a PR scan the disk
		// holds the checked-out revision, which is what we want, but being
		// explicit keeps the two consistent.
		scope := scopes.forFile(f.Path, f.HeadContent)

		headResources, err := parser.ParseFileWithContext(f.Path, f.HeadContent, scope)
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
			// The base revision is parsed without a scope: it exists only to
			// answer "did this attribute's value change", and resolving it
			// against the *head* directory's locals would compare a before
			// value to an after scope.
			baseResources, err := parser.ParseFile(f.Path, f.BaseContent)
			if err == nil {
				for _, r := range baseResources {
					baseByAddr[r.Address()] = r
				}
			}
		}

		in := FileInput{Path: f.Path, HeadResources: headResources, HeadSource: f.HeadContent, BaseResources: baseByAddr}
		for _, rule := range ruleset {
			findings = append(findings, rule.Check(in, kb)...)
		}

		for _, head := range headResources {
			if base, existed := baseByAddr[head.Address()]; existed {
				changedAttrs[head.Address()] = changedAttrsForResource(head, base)
			}
		}
	}

	kept := ignore.Apply(findings, inlineByFile, opts.GlobalIgnore)
	AttachDocURLs(kept, kb)

	return Result{
		Findings:     kept,
		ChangedAttrs: changedAttrs,
	}, nil
}

// AttachDocURLs fills in each finding's DocURL from its resource address.
//
// Done as one pass over the results rather than at each of the two dozen
// places a finding is constructed: the address already identifies the type
// unambiguously, so threading a link through every rule would add a
// parameter everywhere to compute the same thing. Exported because
// plan-based findings are produced outside Run and deserve the same links.
//
// Findings whose type no loaded pack covers keep an empty DocURL — a link to
// a page that may not exist is worse than none.
func AttachDocURLs(findings []report.Finding, kb *schema.KnowledgeBase) {
	if kb == nil {
		return
	}
	cache := map[string]string{}
	for i, f := range findings {
		if f.DocURL != "" || f.Resource == "" {
			continue
		}
		url, seen := cache[f.Resource]
		if !seen {
			if rType, isData, ok := parser.TypeFromAddress(f.Resource); ok {
				url = kb.DocURL(rType, isData)
			}
			cache[f.Resource] = url
		}
		findings[i].DocURL = url
	}
}
