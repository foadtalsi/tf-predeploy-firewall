package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// fixMarkerPrefix opens the hidden HTML comment stamped on every inline
// suggestion. It is how a re-run recognizes a suggestion it already posted:
// unlike the summary comment, GitHub review comments can't be updated as a
// set, so the only way to avoid a wall of duplicates on the third push is to
// look at what's already there and skip it.
const fixMarkerPrefix = "<!-- tf-predeploy-firewall:fix:"

// FixMarker is the identity of a suggestion, stable across pushes.
//
// It hashes what the suggestion *says* — the finding's category, resource,
// file and replacement text — and deliberately not the line it sits on.
// Rebasing or editing code above shifts every line below it; keying on the
// line number would repost the same suggestion after any unrelated edit,
// which is exactly the noise that gets a bot muted.
func FixMarker(f Finding) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{
		string(f.Category), f.Resource, f.File, f.Fix.Text(),
	}, "\x00")))
	return fixMarkerPrefix + hex.EncodeToString(sum[:])[:16] + " -->"
}

// HasFixMarker reports whether an existing review comment body was produced
// for the same finding, i.e. whether posting f again would be a duplicate.
func HasFixMarker(commentBody string, f Finding) bool {
	return strings.Contains(commentBody, FixMarker(f))
}

// ReviewCommentBody renders a finding as the body of an inline PR review
// comment, with its fix inside a GitHub ```suggestion block so the author
// can apply it with the "Commit suggestion" button.
//
// The severity and category are repeated here rather than left to the
// summary comment: an inline comment is read where it lands, in the diff,
// by someone who may never scroll down to the table.
func ReviewCommentBody(f Finding) string {
	var b strings.Builder

	fmt.Fprintf(&b, "**%s %s — %s**\n\n", severityEmoji[f.Severity], f.Severity, categoryDisplay(f.Category))
	b.WriteString(f.Message + "\n\n")

	b.WriteString("```suggestion\n")
	if text := f.Fix.Text(); text != "" {
		b.WriteString(text + "\n")
	}
	b.WriteString("```\n")

	if f.Fix.Note != "" {
		b.WriteString("\n" + f.Fix.Note + "\n")
	}

	b.WriteString("\n" + FixMarker(f) + "\n")
	return b.String()
}
