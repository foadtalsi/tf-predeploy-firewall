package report

import (
	"strings"
	"testing"
)

func fixFinding() Finding {
	return Finding{
		File:     "rds.tf",
		Line:     12,
		Category: CategoryMissingLifecycle,
		Severity: SeverityMedium,
		Resource: "aws_db_instance.prod",
		Message:  "no prevent_destroy guard",
		Fix: &Fix{
			StartLine: 12,
			EndLine:   12,
			Lines:     []string{`resource "aws_db_instance" "prod" {`, "  lifecycle {", "    prevent_destroy = true", "  }"},
		},
	}
}

// The suggestion block is the whole feature: GitHub only renders the
// "Commit suggestion" button for a fenced block opened with exactly
// ```suggestion.
func TestReviewCommentBody_WrapsTheFixInASuggestionBlock(t *testing.T) {
	body := ReviewCommentBody(fixFinding())

	if !strings.Contains(body, "```suggestion\n") {
		t.Fatalf("no suggestion fence in:\n%s", body)
	}
	between := body[strings.Index(body, "```suggestion\n")+len("```suggestion\n"):]
	between = between[:strings.Index(between, "```")]

	want := "resource \"aws_db_instance\" \"prod\" {\n  lifecycle {\n    prevent_destroy = true\n  }\n"
	if between != want {
		t.Errorf("suggestion content:\n%q\nwant:\n%q", between, want)
	}
	if !strings.Contains(body, "no prevent_destroy guard") {
		t.Error("the comment must say why, not just what to paste")
	}
}

func TestReviewCommentBody_IncludesTheNoteWhenTheFixIsNotSelfSufficient(t *testing.T) {
	f := fixFinding()
	f.Fix.Note = "You also need to declare the variable."
	if !strings.Contains(ReviewCommentBody(f), "You also need to declare the variable.") {
		t.Error("a fix that leaves work behind has to say so where it is applied")
	}
}

// The marker is how a re-run recognizes its own suggestions. Keying it on
// the line number would repost everything after any edit above.
func TestFixMarker_IgnoresLineNumberButNotContent(t *testing.T) {
	a := fixFinding()

	moved := fixFinding()
	moved.Line = 400
	moved.Fix.StartLine = 400
	moved.Fix.EndLine = 400

	if FixMarker(a) != FixMarker(moved) {
		t.Error("the same fix further down the file must keep its identity")
	}

	changed := fixFinding()
	changed.Fix.Lines = []string{"something else entirely"}
	if FixMarker(a) == FixMarker(changed) {
		t.Error("a different replacement is a different suggestion and must be posted")
	}

	otherResource := fixFinding()
	otherResource.Resource = "aws_db_instance.staging"
	if FixMarker(a) == FixMarker(otherResource) {
		t.Error("the same fix on a different resource must not be deduplicated away")
	}
}

func TestHasFixMarker_MatchesAnAlreadyPostedComment(t *testing.T) {
	f := fixFinding()
	posted := ReviewCommentBody(f)

	if !HasFixMarker(posted, f) {
		t.Error("a comment produced from this finding must be recognized as a duplicate")
	}
	if HasFixMarker("an unrelated human comment", f) {
		t.Error("unrelated comments must not suppress a suggestion")
	}
}

// The marker has to be invisible in the rendered comment, or every
// suggestion carries a line of noise.
func TestFixMarker_IsAnHTMLComment(t *testing.T) {
	m := FixMarker(fixFinding())
	if !strings.HasPrefix(m, "<!--") || !strings.HasSuffix(m, "-->") {
		t.Errorf("marker %q would render as visible text", m)
	}
}
