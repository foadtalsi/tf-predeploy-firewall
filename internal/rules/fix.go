package rules

import (
	"strings"

	"github.com/hashicorp/hcl/v2"
)

// This file holds the helpers rules use to build report.Fix values —
// replacements that are exact enough for GitHub's "Commit suggestion"
// button to write them into the branch without anyone re-reading them.
//
// Everything here is conservative on purpose. Each helper returns ok=false
// the moment the source doesn't look the way it assumed, and the caller
// then emits the finding with only its human-readable Suggestion. Missing a
// one-click fix costs a click; getting one wrong commits broken HCL.

// lineText returns line n (1-based) of src, without its line ending.
// ok is false if src is absent or n is out of range — which is the normal
// case for callers that never supplied the source, e.g. unit tests that
// build a FileInput by hand.
func lineText(src []byte, n int) (string, bool) {
	if len(src) == 0 || n < 1 {
		return "", false
	}
	lines := strings.Split(string(src), "\n")
	if n > len(lines) {
		return "", false
	}
	return strings.TrimSuffix(lines[n-1], "\r"), true
}

// indentOf returns the leading whitespace of s, so a generated line lines up
// with the code around it. Tabs are preserved as tabs.
func indentOf(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

// opensBlock reports whether a line is a block header we can safely append
// inside — i.e. it ends with `{` and therefore has a body starting on the
// next line. A single-line block (`lifecycle { prevent_destroy = false }`)
// fails this check, which is the point: appending a line after it would put
// the new content outside the braces.
func opensBlock(line string) bool {
	return strings.HasSuffix(strings.TrimRight(line, " \t"), "{")
}

// declaresAttr reports whether line is the declaration of attribute name —
// `name = …`, possibly indented. Used to confirm that the line a range
// points at really is the one-line assignment we intend to overwrite,
// rather than a one-liner block that happens to contain it.
func declaresAttr(line, name string) bool {
	rest := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(rest, name) {
		return false
	}
	rest = strings.TrimLeft(rest[len(name):], " \t")
	return strings.HasPrefix(rest, "=")
}

// insertIntoBlock builds a fix that keeps a block's header line as-is and
// adds lines directly beneath it, indented one level in.
//
// Rewriting the header verbatim rather than regenerating it is deliberate:
// the header may carry a trailing comment, unusual spacing, or `for_each`
// meta-arguments this tool has no business normalizing.
func insertIntoBlock(src []byte, header hcl.Range, add ...string) (start, end int, lines []string, ok bool) {
	line := header.Start.Line
	text, ok := lineText(src, line)
	if !ok || !opensBlock(text) {
		return 0, 0, nil, false
	}
	inner := indentOf(text) + "  "
	out := []string{text}
	for _, a := range add {
		out = append(out, inner+a)
	}
	return line, line, out, true
}

// replaceAttrLine builds a fix that overwrites a single-line attribute
// assignment with newText, keeping the original indentation.
func replaceAttrLine(src []byte, r hcl.Range, attrName, newText string) (start, end int, lines []string, ok bool) {
	if r.Start.Line != r.End.Line {
		return 0, 0, nil, false // a multi-line value; not ours to rewrite
	}
	text, ok := lineText(src, r.Start.Line)
	if !ok || !declaresAttr(text, attrName) {
		return 0, 0, nil, false
	}
	return r.Start.Line, r.Start.Line, []string{indentOf(text) + newText}, true
}
