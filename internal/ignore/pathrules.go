package ignore

import (
	"path"
	"regexp"
	"strings"
	"sync"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

// PathRule suppresses findings under files matching Pattern — a glob
// supporting "**" (any number of path segments, including zero) alongside
// the usual single-segment "*" and "?". This is the large-scale companion
// to the two suppression mechanisms that already existed: an inline
// comment ignores one line, GlobalIgnore (config.yml's ignore_rules)
// ignores one category everywhere, but neither could say "don't scan
// legacy/** at all" without littering every file in that tree with
// comments. Categories, if non-empty, scopes the suppression to just those
// categories under the matched path; empty means "ignore every category
// under this path."
type PathRule struct {
	Pattern    string
	Categories []report.Category
}

func (r PathRule) suppresses(category report.Category) bool {
	if len(r.Categories) == 0 {
		return true
	}
	for _, c := range r.Categories {
		if c == category {
			return true
		}
	}
	return false
}

var (
	globCacheMu sync.Mutex
	globCache   = map[string]*regexp.Regexp{}
)

// globToRegexp compiles a glob pattern (with "**" support) to an anchored
// regexp, caching the result — patterns come from config.yml and are
// re-tested against every finding, so this avoids recompiling per finding.
func globToRegexp(pattern string) *regexp.Regexp {
	globCacheMu.Lock()
	defer globCacheMu.Unlock()
	if re, ok := globCache[pattern]; ok {
		return re
	}

	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); {
		switch {
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(".*")
			i += 2
		case pattern[i] == '*':
			b.WriteString("[^/]*")
			i++
		case pattern[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
			i++
		}
	}
	b.WriteString("$")

	re := regexp.MustCompile(b.String())
	globCache[pattern] = re
	return re
}

// ApplyPathRules removes findings under a path matched by any rule, scoped
// to that rule's Categories. Applied as a final pass over the full finding
// set (phase 1 + phase 2 + custom rules combined) — path-based suppression
// doesn't care which rule engine produced a finding, only where it is.
func ApplyPathRules(findings []report.Finding, rules []PathRule) []report.Finding {
	if len(rules) == 0 {
		return findings
	}

	var out []report.Finding
	for _, f := range findings {
		clean := path.Clean(f.File)
		suppressed := false
		for _, r := range rules {
			if r.suppresses(f.Category) && globToRegexp(r.Pattern).MatchString(clean) {
				suppressed = true
				break
			}
		}
		if !suppressed {
			out = append(out, f)
		}
	}
	return out
}
