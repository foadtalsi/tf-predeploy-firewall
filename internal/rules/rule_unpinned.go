package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// UnpinnedVersionRule flags module sources and provider requirements that
// float instead of naming a version.
//
// An unpinned dependency makes an apply non-reproducible: the plan someone
// reviewed and the plan that runs an hour later can differ because a third
// party moved a branch or published a release, with no commit in this
// repository to explain it. That is a supply-chain exposure — whoever
// controls that ref controls what runs against your cloud account — and it
// is also the single most reliable way to get a plan nobody can reproduce
// when it goes wrong.
//
// It earns its place next to the AI-hallucination rules for a specific
// reason: generated Terraform almost never writes a version constraint. A
// model asked for "a VPC module" emits a source and moves on.
type UnpinnedVersionRule struct{}

// registryModuleSource matches the Terraform Registry's NAMESPACE/NAME/PROVIDER
// (optionally prefixed with a host), which is the form that takes a separate
// `version` argument. Local paths (./x, ../x) and everything else are not
// registry sources.
var registryModuleSource = regexp.MustCompile(`^([a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$`)

// gitRefParam pulls the ?ref= out of a git source. Its absence is the
// problem; `ref=main` is the same problem wearing a name.
var gitRefParam = regexp.MustCompile(`[?&]ref=([^&]+)`)

// mutableGitRef matches refs that are branches or moving pointers rather
// than immutable commits or tags. A 40- or 7-hex-char SHA and anything
// version-shaped are treated as pinned.
var (
	commitSHA   = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
	versionTag  = regexp.MustCompile(`^v?\d+\.\d+`)
	knownMobile = map[string]bool{"main": true, "master": true, "HEAD": true, "develop": true, "trunk": true, "latest": true}
)

func (UnpinnedVersionRule) Check(in FileInput, kb *schema.KnowledgeBase) []report.Finding {
	var findings []report.Finding

	for _, res := range in.HeadResources {
		if res.Kind != parser.KindModule {
			continue
		}
		findings = append(findings, checkModuleSource(in.Path, res)...)
	}

	findings = append(findings, checkRequiredProviders(in.Path, in.HeadSource)...)
	return findings
}

func checkModuleSource(path string, res *parser.Resource) []report.Finding {
	src, ok := res.Attributes["source"]
	if !ok || !src.IsLiteral || src.RawValue == "" {
		return nil
	}
	value := src.RawValue
	line := src.Range.Start.Line

	finding := func(msg, suggestion string) []report.Finding {
		return []report.Finding{{
			File:       path,
			Line:       line,
			Category:   report.CategoryUnpinnedVersion,
			Severity:   report.SeverityMedium,
			Resource:   res.Address(),
			Message:    msg,
			Suggestion: suggestion,
		}}
	}

	switch {
	// A local path is versioned by this repository's own history; there is
	// nothing to pin.
	case strings.HasPrefix(value, "./"), strings.HasPrefix(value, "../"):
		return nil

	case isGitSource(value):
		m := gitRefParam.FindStringSubmatch(value)
		if m == nil {
			return finding(
				fmt.Sprintf("module source %q has no ?ref= — every apply takes whatever the default branch says at that moment, so the plan reviewed here is not the plan that runs", value),
				"source = \""+value+"?ref=v1.2.3\"  # a tag or a commit SHA")
		}
		ref := m[1]
		if commitSHA.MatchString(ref) || versionTag.MatchString(ref) {
			return nil
		}
		if knownMobile[ref] {
			return finding(
				fmt.Sprintf("module source pins ?ref=%s, which is a moving branch — whoever can push to it decides what runs against your cloud account", ref),
				"# pin to a tag or commit instead:\nsource = \""+strings.Replace(value, "ref="+ref, "ref=v1.2.3", 1)+"\"")
		}
		// An unrecognised ref is more likely a tag we don't recognise the
		// shape of than a branch. Saying nothing beats a false accusation.
		return nil

	case registryModuleSource.MatchString(value):
		if v, ok := res.Attributes["version"]; ok && v.IsLiteral && v.RawValue != "" {
			return nil
		}
		return finding(
			fmt.Sprintf("registry module %q declares no version — Terraform will take the newest release each time the module is re-initialised", value),
			"version = \"~> 1.2\"")
	}
	return nil
}

func isGitSource(value string) bool {
	return strings.HasPrefix(value, "git::") ||
		strings.HasPrefix(value, "git@") ||
		strings.Contains(value, "github.com/") ||
		strings.Contains(value, "gitlab.com/") ||
		strings.HasPrefix(value, "hg::")
}

// requiredProviderEntry matches one `name = { ... }` entry inside a
// required_providers block, capturing the name and its body.
var requiredProviderEntry = regexp.MustCompile(`(?s)([a-z][a-z0-9_-]*)\s*=\s*\{(.*?)\}`)

// checkRequiredProviders flags providers declared without a version
// constraint.
//
// This reads the source text rather than the parsed resources because
// `terraform { required_providers { … } }` is a nested block of a
// non-resource block, which the parser deliberately does not model — it
// isn't infrastructure. Matching the block's text is narrow enough to be
// safe and avoids growing the parser for one rule.
func checkRequiredProviders(path string, src []byte) []report.Finding {
	if len(src) == 0 {
		return nil
	}
	body, startLine, ok := requiredProvidersBody(string(src))
	if !ok {
		return nil
	}

	var findings []report.Finding
	for _, m := range requiredProviderEntry.FindAllStringSubmatchIndex(body, -1) {
		name := body[m[2]:m[3]]
		entry := body[m[4]:m[5]]
		if strings.Contains(entry, "version") {
			continue
		}
		findings = append(findings, report.Finding{
			File:     path,
			Line:     startLine + strings.Count(body[:m[0]], "\n"),
			Category: report.CategoryUnpinnedVersion,
			Severity: report.SeverityMedium,
			Resource: "provider." + name,
			Message: fmt.Sprintf(
				"provider %q declares no version constraint — a new major release of it can change or break this configuration with no commit here to explain why", name),
			Suggestion: fmt.Sprintf("%s = {\n  source  = \"hashicorp/%s\"\n  version = \"~> 5.0\"\n}", name, name),
		})
	}
	return findings
}

// requiredProvidersBody extracts the text inside `required_providers { … }`
// and the line it starts on, by brace matching from the keyword.
func requiredProvidersBody(src string) (body string, startLine int, ok bool) {
	idx := strings.Index(src, "required_providers")
	if idx < 0 {
		return "", 0, false
	}
	open := strings.Index(src[idx:], "{")
	if open < 0 {
		return "", 0, false
	}
	open += idx

	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open+1 : i], strings.Count(src[:open], "\n") + 1, true
			}
		}
	}
	return "", 0, false // unbalanced; the HCL parser will report it
}
