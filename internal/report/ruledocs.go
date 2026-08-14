package report

import (
	"fmt"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/ruledef"
)

// docsBaseURL is where the per-rule documentation lives. It points at the
// main branch rather than a tag: a link inside a SARIF upload outlives the
// scanner version that produced it, and a reader following it a year later
// wants the current explanation, not an archived one.
const docsBaseURL = "https://github.com/foadtalsi/tf-predeploy-firewall/blob/main/docs/rules.md"

// The long-form explanation of each category — what it detects, why it is
// worth a build failure, and how to disagree with it — lives in the rule
// pack, not here.
//
// It used to be four hundred lines of Markdown inside Go string literals,
// which meant that improving a sentence a reader found confusing required a
// Go toolchain and a release. It is prose; it belongs in a data file next to
// the rule it explains, and it is now read from there.

// ruleHelp is one category's documentation, resolved from the pack.
type ruleHelp struct {
	fullDescription string
	markdown        string
}

// lookupRuleHelp returns a category's documentation.
//
// A pack that fails to load leaves categories undocumented rather than
// stopping the process: this package only renders: by the time anything
// reaches it, internal/rules has already refused to run against a broken
// pack. The tests in this package assert that every rule has an explanation,
// so an actually-missing entry is caught there rather than shipped.
func lookupRuleHelp(c Category) (ruleHelp, bool) {
	pack, err := ruledef.Builtin()
	if err != nil {
		return ruleHelp{}, false
	}
	d, ok := pack.DocsFor(string(c))
	if !ok {
		return ruleHelp{}, false
	}
	return ruleHelp{fullDescription: d.FullDescription, markdown: d.Markdown}, true
}

// categoryTitle returns the readable label for a category, from the pack.
func categoryTitle(c Category) (string, bool) {
	pack, err := ruledef.Builtin()
	if err != nil {
		return "", false
	}
	d, ok := pack.DocsFor(string(c))
	if !ok || d.Title == "" {
		return "", false
	}
	return d.Title, true
}

// ruleHelpURI links to a category's section in the published rule
// documentation.
func ruleHelpURI(c Category) string {
	return fmt.Sprintf("%s#%s", docsBaseURL, c)
}

// RenderRuleDocs generates docs/rules.md from the rule pack.
//
// The file is generated rather than written by hand because helpUri points
// at it from every SARIF upload: a category whose section doesn't exist is a
// dead link in someone's security dashboard, and the only way to be sure the
// two agree is to have one produce the other. A test regenerates and compares.
//
// Headings are the bare category ID so the anchors helpUri builds
// (#unknown_attribute) are exactly what GitHub generates; the readable label
// goes underneath.
func RenderRuleDocs() string {
	var b strings.Builder

	b.WriteString(`<!-- Generated from internal/ruledef/rules.yaml. Do not edit by hand:
     edit the pack, then run "go test ./internal/report -run TestRuleDocs -update". -->

# Rules

Every finding this scanner produces belongs to one of the categories below.
Each says what it detects, why it is worth interrupting a merge for, and how
to disagree with it — a rule you can't turn off is a rule that gets the whole
tool turned off.

Suppression works at four levels, narrowest first:

| Scope | How |
|---|---|
| One line | ` + "`# tf-firewall-ignore: <category>`" + ` above or on the line |
| One path | ` + "`ignore_paths:`" + ` in ` + "`.github/tf-firewall.yml`" + `, optionally scoped to categories |
| One category, everywhere | ` + "`ignore_rules:`" + ` in the same file |
| Everything that exists today | a committed baseline (` + "`--write-baseline`" + `) — keeps findings visible but non-blocking |

`)

	for _, r := range sarifRules {
		c := Category(r.ID)
		h, ok := lookupRuleHelp(c)
		if !ok {
			continue
		}
		// The help markdown is written to stand alone on a Code Scanning
		// alert page, where "##" is the top level. Nested under a category
		// heading here, it has to drop one level.
		body := strings.ReplaceAll("\n"+h.markdown, "\n## ", "\n### ")

		fmt.Fprintf(&b, "## %s\n\n**%s**\n\n%s\n%s\n\n---\n\n",
			c, categoryDisplay(c), h.fullDescription, body)
	}

	b.WriteString("Custom rules defined in your own config get the category `custom:<id>` " +
		"and are documented by whatever `message:` you give them.\n")

	return b.String()
}
