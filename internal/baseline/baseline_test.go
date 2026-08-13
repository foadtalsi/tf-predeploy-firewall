package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/foadtalsi/tf-predeploy-firewall/internal/report"
)

func finding(cat report.Category, resource, file, msg string, line int) report.Finding {
	return report.Finding{
		Category: cat, Resource: resource, File: file, Message: msg, Line: line,
		Severity: report.SeverityCritical,
	}
}

// The whole point: what was already there stops blocking, what is new does not.
func TestApply_AcceptsPreExistingButNotNewFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	existing := []report.Finding{
		finding(report.CategoryTutorialPattern, "aws_db_instance.legacy", "legacy.tf", "hardcoded password", 12),
	}
	if err := Write(path, existing, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatalf("Write: %v", err)
	}

	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got := b.Apply([]report.Finding{
		existing[0],
		finding(report.CategoryTutorialPattern, "aws_db_instance.brand_new", "new.tf", "hardcoded password", 3),
	})

	if !got[0].Waived {
		t.Error("a finding recorded in the baseline must not block")
	}
	if got[0].WaiverNote == "" {
		t.Error("an accepted finding must say why it was accepted")
	}
	if got[1].Waived {
		t.Error("a finding absent from the baseline must still block — this is the entire feature")
	}
}

// Lines move when unrelated code is edited above. A baseline that broke on
// that would be abandoned within a week.
func TestApply_MatchesRegardlessOfLineNumber(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := Write(path, []report.Finding{
		finding(report.CategoryTutorialPattern, "aws_db_instance.legacy", "legacy.tf", "hardcoded password", 12),
	}, ""); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, _ := Load(path)

	// Same finding, now 40 lines further down, with a reworded message.
	moved := finding(report.CategoryTutorialPattern, "aws_db_instance.legacy", "legacy.tf",
		"completely different wording after a scanner upgrade", 52)

	got := b.Apply([]report.Finding{moved})
	if !got[0].Waived {
		t.Error("baseline must match on category+resource+file, not on line or message")
	}
}

// A different category on the same resource is a different problem.
func TestApply_DoesNotMatchAcrossCategories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := Write(path, []report.Finding{
		finding(report.CategoryTutorialPattern, "aws_db_instance.legacy", "legacy.tf", "hardcoded password", 12),
	}, ""); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, _ := Load(path)

	got := b.Apply([]report.Finding{
		finding(report.CategoryMissingLifecycle, "aws_db_instance.legacy", "legacy.tf", "no prevent_destroy", 1),
	})
	if got[0].Waived {
		t.Error("accepting one category on a resource must not accept a different one")
	}
}

func TestStale_CountsEntriesThatMatchedNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")

	if err := Write(path, []report.Finding{
		finding(report.CategoryTutorialPattern, "aws_db_instance.fixed", "a.tf", "x", 1),
		finding(report.CategoryTutorialPattern, "aws_db_instance.still_here", "b.tf", "y", 1),
	}, ""); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, _ := Load(path)

	b.Apply([]report.Finding{
		finding(report.CategoryTutorialPattern, "aws_db_instance.still_here", "b.tf", "y", 1),
	})

	if b.Size() != 2 {
		t.Errorf("Size = %d, want 2", b.Size())
	}
	if b.Stale() != 1 {
		t.Errorf("Stale = %d, want 1 — a fixed finding's entry should be reported as prunable", b.Stale())
	}
}

// A missing baseline is the normal state for most repos, not an error.
func TestLoad_MissingFileIsNotAnError(t *testing.T) {
	b, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("a missing baseline should be silently absent, got %v", err)
	}
	if b != nil {
		t.Error("expected no baseline")
	}
	// A nil baseline must be safe to use.
	in := []report.Finding{finding(report.CategoryTutorialPattern, "r", "f", "m", 1)}
	if got := b.Apply(in); got[0].Waived {
		t.Error("a nil baseline must accept nothing")
	}
	if b.Size() != 0 || b.Stale() != 0 {
		t.Error("a nil baseline must report empty")
	}
}

// Refusing an unknown format is deliberate: silently ignoring fields we don't
// understand could suppress findings the author never agreed to.
func TestLoad_RejectsUnknownFormatVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte(`{"format_version": 99, "entries": []}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected a future format version to be rejected")
	}
}

func TestLoad_CorruptFileIsAnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("a corrupt baseline must be an error, not silently treated as empty")
	}
}

// Regenerating an unchanged repo must produce an identical file, or the
// baseline shows up as noise in every diff.
func TestWrite_IsDeterministicAndDeduplicated(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	b := filepath.Join(dir, "b.json")

	findings := []report.Finding{
		finding(report.CategoryMissingLifecycle, "aws_s3_bucket.z", "z.tf", "m", 9),
		finding(report.CategoryTutorialPattern, "aws_db_instance.a", "a.tf", "m", 1),
		// Duplicate of the first, as a second scan pass might produce.
		finding(report.CategoryMissingLifecycle, "aws_s3_bucket.z", "z.tf", "m", 9),
	}

	if err := Write(a, findings, "t"); err != nil {
		t.Fatal(err)
	}
	// Same findings in a different order.
	if err := Write(b, []report.Finding{findings[2], findings[1], findings[0]}, "t"); err != nil {
		t.Fatal(err)
	}

	ba, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if string(ba) != string(bb) {
		t.Error("baseline output must not depend on finding order")
	}

	loaded, err := Load(a)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Size() != 2 {
		t.Errorf("expected duplicates collapsed to 2 entries, got %d", loaded.Size())
	}
}
