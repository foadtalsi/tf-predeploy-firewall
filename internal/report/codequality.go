package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// GitLab Code Quality output — the CodeClimate-derived JSON that GitLab's
// merge request widget renders natively. It is GitLab's counterpart to
// uploading SARIF on GitHub: findings appear in the MR UI itself, with
// degradation arrows against the target branch, no comment-posting token
// required.
//
// https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format

type codeQualityIssue struct {
	Description string              `json:"description"`
	CheckName   string              `json:"check_name"`
	Fingerprint string              `json:"fingerprint"`
	Severity    string              `json:"severity"`
	Location    codeQualityLocation `json:"location"`
}

type codeQualityLocation struct {
	Path  string           `json:"path"`
	Lines codeQualityLines `json:"lines"`
}

type codeQualityLines struct {
	Begin int `json:"begin"`
}

// severityToCodeQuality maps onto GitLab's accepted set
// (info/minor/major/critical/blocker). "blocker" is reserved: this tool's
// notion of blocking lives in its exit code and threshold, and claiming the
// word in a UI that didn't consult the threshold would misstate the tool.
var severityToCodeQuality = map[Severity]string{
	SeverityLow:      "info",
	SeverityMedium:   "minor",
	SeverityHigh:     "major",
	SeverityCritical: "critical",
}

// RenderCodeQuality serialises findings as a GitLab Code Quality report.
//
// The fingerprint deliberately excludes the line number — GitLab diffs
// issues across pipelines by fingerprint, and one that shifted with the
// line would make every rebase look like findings appearing and vanishing.
// It does include the message, unlike the baseline's coarser key: two
// same-category findings on one resource (two hardcoded credentials, say)
// must not collapse into a single widget row.
func RenderCodeQuality(findings []Finding) ([]byte, error) {
	issues := make([]codeQualityIssue, 0, len(findings))
	for _, f := range findings {
		if f.Waived {
			continue // accepted findings are decisions, not open issues
		}
		sum := sha256.Sum256([]byte(string(f.Category) + "\x00" + f.Resource + "\x00" + f.File + "\x00" + f.Message))
		issues = append(issues, codeQualityIssue{
			Description: f.Resource + ": " + f.Message,
			CheckName:   string(f.Category),
			Fingerprint: hex.EncodeToString(sum[:]),
			Severity:    severityToCodeQuality[f.Severity],
			Location: codeQualityLocation{
				Path:  f.File,
				Lines: codeQualityLines{Begin: f.Line},
			},
		})
	}
	return json.MarshalIndent(issues, "", "  ")
}
