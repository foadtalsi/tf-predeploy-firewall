// Package severity decides whether a set of findings should block a PR.
package severity

import "github.com/foadtalsi/tf-predeploy-firewall/internal/report"

// ShouldBlock reports whether any finding meets or exceeds threshold.
func ShouldBlock(findings []report.Finding, threshold report.Severity) bool {
	for _, f := range findings {
		if f.Severity.AtLeast(threshold) {
			return true
		}
	}
	return false
}
