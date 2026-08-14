// Package forge holds what posting scan results to a code host looks like
// when it isn't GitHub-shaped: the shared vocabulary (inline comments,
// suggestion outcomes) and the diff-hunk arithmetic every host needs,
// because they all share the same constraint — an inline comment can only
// land on a line the diff contains.
//
// The host-specific packages (githubpr, gitlabmr) implement Forge. main
// picks one from the CI environment it finds itself in.
package forge

import (
	"strconv"
	"strings"
)

// InlineComment is one comment to attach to a line range of the diff, with
// Body already rendered in the host's own suggestion syntax — GitHub and
// GitLab both have one-click-applicable suggestion blocks, but the fence
// grammar differs, so rendering happens before this type is built.
type InlineComment struct {
	// Path is the file path relative to the repository root.
	Path string

	// StartLine and Line bound the commented range in the post-change file,
	// inclusive. A single-line comment sets them equal (or leaves StartLine
	// zero).
	StartLine int
	Line      int

	Body string

	// Marker uniquely identifies this comment's content. If a comment
	// already on the change contains it, this one is skipped — inline
	// comments can't be upserted as a set the way a summary comment can, so
	// recognizing one's own past comments is the only defence against
	// stacking duplicates on every push.
	Marker string
}

// SuggestionOutcome accounts for every comment handed to PostSuggestions.
// Nothing is dropped silently: a suggestion that never appears because its
// line isn't in the diff looks identical, from the outside, to a scanner
// that found nothing.
type SuggestionOutcome struct {
	Posted       int
	AlreadyThere int
	OutsideDiff  int
}

// Forge is a code host the scanner can report to.
type Forge interface {
	// UpsertComment finds the existing summary comment containing marker
	// and replaces its body, or creates one.
	UpsertComment(body, marker string) error

	// PostSuggestions attaches the comments as inline review comments,
	// filtering out anything the host would reject and anything already
	// posted. headSHA, when non-empty, pins the batch to the revision the
	// scan actually ran against.
	PostSuggestions(summary string, comments []InlineComment, headSHA string) (SuggestionOutcome, error)
}

// PatchLineNumbers walks a unified diff patch hunk by hunk and returns the
// set of post-change line numbers it covers — added and context lines both,
// since a finding on an unchanged resource header is anchored to a context
// line. Deleted lines have no position in the new file and are excluded.
func PatchLineNumbers(patch string) map[int]bool {
	lines := map[int]bool{}
	newLine := 0

	// The trailing newline would otherwise yield one phantom line past the
	// end of the last hunk, and a comment there is rejected by every host.
	for _, l := range strings.Split(strings.TrimSuffix(patch, "\n"), "\n") {
		if strings.HasPrefix(l, "@@") {
			if n, ok := hunkNewStart(l); ok {
				newLine = n
			}
			continue
		}
		if newLine == 0 {
			continue // text before the first hunk header
		}
		switch {
		case strings.HasPrefix(l, "+"), strings.HasPrefix(l, " "), l == "":
			// Added or unchanged: this line exists in the new file. An empty
			// string is an unchanged blank line whose leading space was
			// trimmed somewhere along the way.
			lines[newLine] = true
			newLine++
		case strings.HasPrefix(l, "-"):
			// Deleted: present only in the old file; the counter must not
			// advance.
		default:
			// "\ No newline at end of file" and anything else unrecognized.
		}
	}
	return lines
}

// hunkNewStart reads the post-change starting line out of a hunk header,
// e.g. "@@ -12,7 +14,9 @@ resource ..." -> 14.
func hunkNewStart(header string) (int, bool) {
	plus := strings.Index(header, "+")
	if plus < 0 {
		return 0, false
	}
	rest := header[plus+1:]
	end := strings.IndexAny(rest, ", ")
	if end < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// LinesInDiff reports whether every line of the comment's range is
// commentable in the given per-file diff line sets.
func LinesInDiff(diffLines map[string]map[int]bool, cm InlineComment) bool {
	inFile, ok := diffLines[cm.Path]
	if !ok {
		return false
	}
	start := cm.StartLine
	if start <= 0 {
		start = cm.Line
	}
	for l := start; l <= cm.Line; l++ {
		if !inFile[l] {
			return false
		}
	}
	return true
}
