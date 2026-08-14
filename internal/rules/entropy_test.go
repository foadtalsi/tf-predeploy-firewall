package rules

import (
	"strings"
	"testing"
)

// Both directions matter, and the negatives matter more: this check runs on
// every string literal in every scanned file, and flagging an ARN as a
// leaked secret is how a rule gets ignored.
func TestLooksLikeSecret(t *testing.T) {
	// Random base64-ish tokens of the kind SaaS vendors mint. Deliberately
	// NOT in any real vendor's format — GitHub's own push protection blocks
	// commits containing realistic-looking keys, which is both correct of
	// it and exactly the class of string this detector exists to catch.
	secrets := []string{
		"xoxb4Qm7Zt2LkVpR9sWyE3uHnJd6FbCa8gXe",
		"Vt5wYq2Jn8RkLp3zXcB7dHm4gFa9eSu6TbNr",
		"9fXk2LmQ8vRt4YwZ7pBn3JhGd5cSe6aUxNrM",
	}
	notSecrets := []string{
		"arn:aws:iam::123456789012:role/service-role/my-function-role",
		"/subscriptions/601d9db8-ff41-4a4c-9e2f-a886a4a6a1b3/resourceGroups/rg",
		"ami-0abcdef1234567890",
		"subnet-00112233445566778",
		"https://example.com/very/long/path/to/an/object?with=query",
		"601d9db8-ff41-4a4c-9e2f-a886a4a6a1b3", // UUID: dashes cap its entropy
		"this is a human sentence long enough to measure",
		"prod-eu-west-1-database-primary-replica", // long but structured
		"short",
	}

	for _, s := range secrets {
		if _, ok := looksLikeSecret(s); !ok {
			t.Errorf("%.20q… should be flagged (entropy %.2f)", s, shannonEntropy(s))
		}
	}
	for _, s := range notSecrets {
		if _, ok := looksLikeSecret(s); ok {
			t.Errorf("%.40q must NOT be flagged (entropy %.2f) — false positives are how this rule dies", s, shannonEntropy(s))
		}
	}
}

// End to end through the rule: a high-entropy value in an arbitrary
// attribute is exactly the case the named-attribute check can't reach.
func TestTutorialPattern_FlagsHighEntropyValueInUnnamedAttribute(t *testing.T) {
	src := `resource "aws_instance" "web" {
  some_config_field = "xoxb4Qm7Zt2LkVpR9sWyE3uHnJd6FbCa8gXe"
}
`
	findings := runOn(t, TutorialPatternRule{}, src)

	var hit bool
	for _, f := range findings {
		if strings.Contains(f.Message, "high-entropy string") {
			hit = true
			if f.Severity != "high" {
				t.Errorf("severity = %s — a statistical guess must not claim critical", f.Severity)
			}
		}
	}
	if !hit {
		t.Fatal("high-entropy value went undetected")
	}
}

// The named-attribute and known-format checks take precedence: an AKIA key
// must be reported as an AWS key, not vaguely as entropy.
func TestTutorialPattern_KnownFormatsWinOverEntropy(t *testing.T) {
	src := `resource "aws_instance" "web" {
  user_data = "AKIAIOSFODNN7EXAMPLEAKIAIOSFODNN7EXAMPLE"
}
`
	for _, f := range runOn(t, TutorialPatternRule{}, src) {
		if strings.Contains(f.Message, "high-entropy string") {
			t.Error("a recognized credential format must not double-report as entropy")
		}
	}
}
