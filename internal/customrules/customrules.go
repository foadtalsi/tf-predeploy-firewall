// Package customrules lets an org define its own detection rules
// declaratively (YAML: resource type + attribute/block + regex pattern),
// without this tool ever executing arbitrary org-supplied code. A DSL
// interpreter with no eval/exec surface is a deliberate security boundary:
// this project runs inside other people's CI pipelines, so "let customers
// write code that runs here" is not a trade-off worth taking for a
// convenience feature.
package customrules

import (
	"fmt"
	"regexp"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/rules"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
	"gopkg.in/yaml.v3"
)

// Rule is one custom detection rule, as authored in YAML.
type Rule struct {
	ID           string `yaml:"id"`
	ResourceType string `yaml:"resource_type"`       // exact type, or "*" for any resource
	Block        string `yaml:"block,omitempty"`     // nested block type to search within (e.g. "ingress"); omit to check the resource's top-level attributes
	Attribute    string `yaml:"attribute,omitempty"` // attribute name to check; omit to just flag every match of resource_type/block
	Pattern      string `yaml:"pattern,omitempty"`   // regex tested against the attribute's literal value
	Negate       bool   `yaml:"negate,omitempty"`    // flag when the pattern does NOT match, or the attribute is absent — for "must have X" rules
	Severity     string `yaml:"severity"`
	Message      string `yaml:"message"`

	compiled *regexp.Regexp
}

// Config is a full custom rule set, as loaded from an org's YAML config.
type Config struct {
	Rules []Rule `yaml:"custom_rules"`
}

// Load parses and validates a custom rule set. Every rule is validated at
// load time (valid severity, valid regex, required fields present) so a
// typo in an org's config fails the scan loudly instead of silently
// matching nothing.
func Load(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing custom rules: %w", err)
	}
	for i := range cfg.Rules {
		if err := cfg.Rules[i].validate(); err != nil {
			return nil, fmt.Errorf("custom rule %d: %w", i, err)
		}
	}
	return &cfg, nil
}

var validSeverities = map[string]bool{"low": true, "medium": true, "high": true, "critical": true}

func (r *Rule) validate() error {
	if r.ID == "" {
		return fmt.Errorf("id is required")
	}
	if r.ResourceType == "" {
		return fmt.Errorf("resource_type is required")
	}
	if !validSeverities[r.Severity] {
		return fmt.Errorf("severity must be one of low/medium/high/critical, got %q", r.Severity)
	}
	if r.Message == "" {
		return fmt.Errorf("message is required")
	}
	if r.Pattern == "" && r.Attribute != "" {
		return fmt.Errorf("attribute %q is set but pattern is empty — a pattern is required to evaluate the attribute's value (omit both to just flag the resource's/block's presence)", r.Attribute)
	}
	if r.Pattern != "" {
		compiled, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("invalid pattern: %w", err)
		}
		r.compiled = compiled
	}
	return nil
}

// ruleSet adapts Config into a rules.Rule so it drops straight into the
// same engine (rules.Run) as every built-in rule.
type ruleSet struct{ cfg *Config }

// AsEngineRule wraps a loaded Config as a rules.Rule for rules.Run.
func (c *Config) AsEngineRule() rules.Rule {
	return ruleSet{cfg: c}
}

func (rs ruleSet) Check(in rules.FileInput, aws *schema.AWS) []report.Finding {
	var findings []report.Finding
	for _, res := range in.HeadResources {
		for _, r := range rs.cfg.Rules {
			findings = append(findings, r.check(in.Path, res)...)
		}
	}
	return findings
}

func (r *Rule) check(path string, res *parser.Resource) []report.Finding {
	if r.ResourceType != "*" && r.ResourceType != res.Type {
		return nil
	}

	if r.Block != "" {
		var findings []report.Finding
		for _, b := range res.Blocks {
			if b.Type != r.Block {
				continue
			}
			if f, ok := r.checkAttrs(path, res, b.Attributes, b.Range.Start.Line); ok {
				findings = append(findings, f)
			}
		}
		return findings
	}

	if f, ok := r.checkAttrs(path, res, res.Attributes, res.DefRange.Start.Line); ok {
		return []report.Finding{f}
	}
	return nil
}

// checkAttrs evaluates one rule against one set of attributes (either a
// resource's top-level attributes or one nested block's), returning a
// finding and true if it fires.
func (r *Rule) checkAttrs(path string, res *parser.Resource, attrs map[string]*parser.Attribute, fallbackLine int) (report.Finding, bool) {
	line := fallbackLine
	matched := false

	if r.Attribute == "" {
		// No attribute specified: this rule flags the mere presence of the
		// resource/block (e.g. "don't use aws_iam_user, use aws_iam_role").
		matched = true
	} else {
		attr, present := attrs[r.Attribute]
		switch {
		case present && attr.IsLiteral && r.compiled != nil:
			line = attr.Range.Start.Line
			matched = r.compiled.MatchString(attr.RawValue) != r.Negate
		case present && !r.Negate:
			// Attribute exists but isn't a literal we can pattern-match (a
			// variable/expression) — can't evaluate it, so don't guess.
			matched = false
		case !present:
			// Missing attribute only "matches" for a negated rule (i.e. "this
			// attribute must be present and match the pattern").
			matched = r.Negate
		}
	}

	if !matched {
		return report.Finding{}, false
	}

	return report.Finding{
		File:     path,
		Line:     line,
		Category: report.Category("custom:" + r.ID),
		Severity: report.Severity(r.Severity),
		Resource: res.Address(),
		Message:  r.Message,
	}, true
}
