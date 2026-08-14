package rules

import (
	"strings"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/parser"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
	"github.com/foadtalsi/tf-predeploy-firewall/internal/schema"
)

// runOn parses src and runs one rule over it, with the source attached so
// fixes can be built.
func runOn(t *testing.T, rule Rule, src string) []report.Finding {
	t.Helper()
	resources, err := parser.ParseFile("main.tf", []byte(src))
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	kb, err := schema.Load()
	if err != nil {
		t.Fatalf("schema.Load: %v", err)
	}
	return rule.Check(FileInput{
		Path:          "main.tf",
		HeadResources: resources,
		HeadSource:    []byte(src),
	}, kb)
}

func onlyFix(t *testing.T, findings []report.Finding) *report.Fix {
	t.Helper()
	var found *report.Fix
	for _, f := range findings {
		if f.Fix == nil {
			continue
		}
		if found != nil {
			t.Fatalf("expected exactly one fix, got a second: %v", f.Fix.Lines)
		}
		found = f.Fix
	}
	if found == nil {
		t.Fatal("expected a fix, got none")
	}
	return found
}

// A fix is committed to the branch by a button click, so what it produces
// must be exactly what the file should contain — not approximately.
func TestFix_AddsLifecycleBlockInsideResourceHeader(t *testing.T) {
	src := `resource "aws_db_instance" "prod" {
  identifier = "prod"
}
`
	fix := onlyFix(t, runOn(t, MissingLifecycleRule{}, src))

	if fix.StartLine != 1 || fix.EndLine != 1 {
		t.Errorf("fix should replace the header line only, got %d-%d", fix.StartLine, fix.EndLine)
	}
	want := `resource "aws_db_instance" "prod" {
  lifecycle {
    prevent_destroy = true
  }`
	if fix.Text() != want {
		t.Errorf("fix text:\n%s\n\nwant:\n%s", fix.Text(), want)
	}
	// Applying it must leave the file parseable, which is the only property
	// that actually matters once the button is pressed.
	assertApplyParses(t, src, fix)
}

func TestFix_AddsPreventDestroyToAnExistingLifecycleBlock(t *testing.T) {
	src := `resource "aws_db_instance" "prod" {
  identifier = "prod"

  lifecycle {
    ignore_changes = [tags]
  }
}
`
	fix := onlyFix(t, runOn(t, MissingLifecycleRule{}, src))

	if fix.StartLine != 4 {
		t.Errorf("fix should anchor on the lifecycle header (line 4), got %d", fix.StartLine)
	}
	want := "  lifecycle {\n    prevent_destroy = true"
	if fix.Text() != want {
		t.Errorf("fix text:\n%q\nwant:\n%q", fix.Text(), want)
	}
	assertApplyParses(t, src, fix)
}

func TestFix_FlipsAnExplicitFalse(t *testing.T) {
	src := `resource "aws_db_instance" "prod" {
  identifier = "prod"

  lifecycle {
    prevent_destroy = false
  }
}
`
	fix := onlyFix(t, runOn(t, MissingLifecycleRule{}, src))

	if fix.Text() != "    prevent_destroy = true" {
		t.Errorf("fix text: %q — indentation must match the line it replaces", fix.Text())
	}
	if fix.StartLine != 5 || fix.EndLine != 5 {
		t.Errorf("expected a single-line replacement at line 5, got %d-%d", fix.StartLine, fix.EndLine)
	}
	assertApplyParses(t, src, fix)
}

func TestFix_ReplacesHardcodedCredentialWithAVariable(t *testing.T) {
	src := `resource "aws_db_instance" "prod" {
  identifier = "prod"
  password   = "hunter2"
}
`
	findings := runOn(t, TutorialPatternRule{}, src)

	var fix *report.Fix
	for _, f := range findings {
		if f.Fix != nil {
			fix = f.Fix
		}
	}
	if fix == nil {
		t.Fatal("a hardcoded password written inline is exactly the case a one-click fix exists for")
	}
	if fix.Text() != "  password = var.prod_password" {
		t.Errorf("fix text: %q", fix.Text())
	}
	if !strings.Contains(fix.Note, `variable "prod_password"`) {
		t.Error("the note must carry the variable declaration the fix leaves undeclared")
	}
	if !strings.Contains(fix.Note, "rotate") {
		t.Error("a committed secret stays in git history; the note has to say so")
	}
	assertApplyParses(t, src, fix)
}

// The literal lives in the variable's default, not on this line. Rewriting
// `password = var.db_password` into `password = var.something_else` would
// look like a fix and change nothing.
func TestFix_NotOfferedWhenTheValueCameThroughAReference(t *testing.T) {
	src := `variable "db_password" { default = "hunter2" }

resource "aws_db_instance" "prod" {
  identifier = "prod"
  password   = var.db_password
}
`
	scope := parser.BuildScope(map[string][]byte{"main.tf": []byte(src)})
	resources, err := parser.ParseFileWithContext("main.tf", []byte(src), scope)
	if err != nil {
		t.Fatalf("ParseFileWithContext: %v", err)
	}
	kb, _ := schema.Load()
	findings := TutorialPatternRule{}.Check(FileInput{
		Path: "main.tf", HeadResources: resources, HeadSource: []byte(src),
	}, kb)

	var flagged bool
	for _, f := range findings {
		if f.Category != report.CategoryTutorialPattern || !strings.Contains(f.Message, "password") {
			continue
		}
		flagged = true
		if f.Fix != nil {
			t.Errorf("no one-click fix should be offered here: %q", f.Fix.Text())
		}
	}
	if !flagged {
		t.Fatal("the finding itself must still be reported")
	}
}

// A one-line block would put the inserted content outside the braces.
func TestFix_NotOfferedForASingleLineBlock(t *testing.T) {
	src := `resource "aws_db_instance" "prod" { identifier = "prod" }
`
	for _, f := range runOn(t, MissingLifecycleRule{}, src) {
		if f.Fix != nil {
			t.Errorf("expected no fix for a single-line resource block, got:\n%s", f.Fix.Text())
		}
	}
}

// Rules that never received the source must degrade to no fix rather than
// guessing at what the line said.
func TestFix_NotOfferedWithoutSource(t *testing.T) {
	src := `resource "aws_db_instance" "prod" {
  identifier = "prod"
}
`
	resources, err := parser.ParseFile("main.tf", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := schema.Load()
	findings := MissingLifecycleRule{}.Check(FileInput{Path: "main.tf", HeadResources: resources}, kb)
	for _, f := range findings {
		if f.Fix != nil {
			t.Error("a fix built without the file source cannot be exact and must not be offered")
		}
		if f.Suggestion == "" {
			t.Error("the human-readable suggestion must survive regardless")
		}
	}
}

func TestFix_PreservesTabIndentation(t *testing.T) {
	src := "resource \"aws_db_instance\" \"prod\" {\n\tlifecycle {\n\t\tprevent_destroy = false\n\t}\n}\n"
	fix := onlyFix(t, runOn(t, MissingLifecycleRule{}, src))
	if fix.Text() != "\t\tprevent_destroy = true" {
		t.Errorf("fix text %q — tabs in the original must not become spaces", fix.Text())
	}
}

// assertApplyParses splices the fix into src the way GitHub's "Commit
// suggestion" button does and checks the result is still valid HCL.
func assertApplyParses(t *testing.T, src string, fix *report.Fix) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(src, "\n"), "\n")
	if fix.StartLine < 1 || fix.EndLine > len(lines) {
		t.Fatalf("fix range %d-%d is outside the file's %d lines", fix.StartLine, fix.EndLine, len(lines))
	}

	out := append([]string{}, lines[:fix.StartLine-1]...)
	out = append(out, fix.Lines...)
	out = append(out, lines[fix.EndLine:]...)
	applied := strings.Join(out, "\n") + "\n"

	if _, err := parser.ParseFile("main.tf", []byte(applied)); err != nil {
		t.Fatalf("applying the fix produced unparseable HCL: %v\n---\n%s", err, applied)
	}
}

// The fix has to actually fix the finding, not just parse.
func TestFix_ApplyingItClearsTheFinding(t *testing.T) {
	for name, src := range map[string]string{
		"no lifecycle block": "resource \"aws_db_instance\" \"prod\" {\n  identifier = \"prod\"\n}\n",
		"empty lifecycle":    "resource \"aws_db_instance\" \"prod\" {\n  lifecycle {\n    ignore_changes = [tags]\n  }\n}\n",
		"explicit false":     "resource \"aws_db_instance\" \"prod\" {\n  lifecycle {\n    prevent_destroy = false\n  }\n}\n",
	} {
		t.Run(name, func(t *testing.T) {
			fix := onlyFix(t, runOn(t, MissingLifecycleRule{}, src))

			lines := strings.Split(strings.TrimSuffix(src, "\n"), "\n")
			out := append([]string{}, lines[:fix.StartLine-1]...)
			out = append(out, fix.Lines...)
			out = append(out, lines[fix.EndLine:]...)
			applied := strings.Join(out, "\n") + "\n"

			if got := runOn(t, MissingLifecycleRule{}, applied); len(got) != 0 {
				t.Errorf("finding survived its own fix: %v\n---\n%s", got[0].Message, applied)
			}
		})
	}
}
