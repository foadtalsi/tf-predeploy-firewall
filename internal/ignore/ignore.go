// Package ignore implements the two-tier suppression mechanism:
//
//  1. Inline comment on the same line or the line immediately above a finding:
//     # tf-firewall-ignore: unknown_attribute,tutorial_pattern
//
//  2. Global list in config.yml (ignore_rules) that suppresses a category
//     across all files.
package ignore

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

const directivePrefix = "tf-firewall-ignore:"

// ParseComments scans raw .tf source and returns a map of
// 1-indexed line number -> set of categories suppressed on that line.
// A directive on line N suppresses findings on line N and line N+1,
// so the caller can place the comment either on the attribute line itself
// or on the line above it.
func ParseComments(src []byte) map[int]map[report.Category]bool {
	out := make(map[int]map[report.Category]bool)
	scanner := bufio.NewScanner(bytes.NewReader(src))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		idx := strings.Index(line, "#")
		if idx < 0 {
			continue
		}
		comment := strings.TrimSpace(line[idx+1:])
		if !strings.HasPrefix(comment, directivePrefix) {
			continue
		}
		cats := parseCategoryList(strings.TrimPrefix(comment, directivePrefix))
		// Suppress on this line and the next (directive above the attribute).
		for _, n := range []int{lineNum, lineNum + 1} {
			if out[n] == nil {
				out[n] = make(map[report.Category]bool)
			}
			for _, c := range cats {
				out[n][c] = true
			}
		}
	}
	return out
}

func parseCategoryList(s string) []report.Category {
	var cats []report.Category
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			cats = append(cats, report.Category(part))
		}
	}
	return cats
}

// Apply removes findings that are suppressed either by an inline directive
// in their source file or by the global ignore list.
func Apply(
	findings []report.Finding,
	inlineByFile map[string]map[int]map[report.Category]bool,
	globalIgnore []report.Category,
) []report.Finding {
	globalSet := make(map[report.Category]bool, len(globalIgnore))
	for _, c := range globalIgnore {
		globalSet[c] = true
	}

	var out []report.Finding
	for _, f := range findings {
		if globalSet[f.Category] {
			continue
		}
		if fileMap, ok := inlineByFile[f.File]; ok {
			if lineMap, ok := fileMap[f.Line]; ok {
				// "all" suppresses every category on this line
				if lineMap[report.Category("all")] || lineMap[f.Category] {
					continue
				}
			}
		}
		out = append(out, f)
	}
	return out
}
