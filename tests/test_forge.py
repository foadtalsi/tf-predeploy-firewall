"""Test shared diff-line arithmetic used to anchor inline suggestions on code hosts."""

from __future__ import annotations

import pytest

from tfpdf.forge import InlineComment, lines_in_diff, patch_line_numbers

# A realistic two-hunk patch: one edit near the top, one further down.
PATCH = """@@ -1,4 +1,5 @@
 resource "aws_db_instance" "prod" {
   identifier = "prod-db"
-  engine     = "mysql"
+  engine     = "postgres"
+  password   = "hunter2"
 }
@@ -20,3 +21,4 @@ resource "aws_s3_bucket" "logs" {
   bucket = "logs"
+  acl    = "public-read"
 }
"""


def test_patch_line_numbers_covers_added_and_context_lines() -> None:
    """Unchanged context lines can anchor findings on resource headers."""
    lines = patch_line_numbers(PATCH)
    # First hunk starts at new line 1 and covers 5 lines (3 context + 2 added;
    # the deleted line does not advance the counter).
    assert lines >= {1, 2, 3, 4, 5}
    # Second hunk starts at new line 21 and covers 3.
    assert lines >= {21, 22, 23}


def test_patch_line_numbers_excludes_deleted_lines() -> None:
    """Deleted lines must not advance updated-file line numbers."""
    lines = patch_line_numbers(PATCH)
    # The hunk header says +1,5 — exactly five lines exist in the new file.
    assert 6 not in lines
    # Nothing between the two hunks is commentable.
    assert not (lines & set(range(6, 21)))


def test_patch_line_numbers_ignores_text_before_the_first_hunk() -> None:
    patch = "diff --git a/main.tf b/main.tf\n--- a/main.tf\n+++ b/main.tf\n@@ -1,1 +1,1 @@\n+x\n"
    assert patch_line_numbers(patch) == {1}


def test_patch_line_numbers_ignores_the_no_newline_marker() -> None:
    patch = "@@ -1,1 +1,2 @@\n a\n+b\n\\ No newline at end of file\n"
    assert patch_line_numbers(patch) == {1, 2}


def test_patch_line_numbers_does_not_invent_a_trailing_line() -> None:
    """A trailing newline must not create a commentable phantom line."""
    assert patch_line_numbers("@@ -1,1 +1,1 @@\n+only\n") == {1}


def test_patch_line_numbers_on_an_empty_patch() -> None:
    assert patch_line_numbers("") == set()


@pytest.mark.parametrize(
    ("header", "want"),
    [
        ("@@ -12,7 +14,9 @@ resource x {", 14),
        ("@@ -0,0 +1 @@", 1),
        ("@@ malformed @@", None),
        ("@@ -1,1 +0,0 @@", None),  # a start line of 0 is not a real position
    ],
)
def test_hunk_new_start(header: str, want: int | None) -> None:
    from tfpdf.forge import _hunk_new_start

    assert _hunk_new_start(header) == want


def test_lines_in_diff_requires_the_whole_range() -> None:
    """Require the whole replacement range to be inside the diff."""
    diff_lines = {"main.tf": {10, 11, 12}}

    assert lines_in_diff(diff_lines, InlineComment(path="main.tf", line=11))
    assert lines_in_diff(diff_lines, InlineComment(path="main.tf", start_line=10, line=12))
    assert not lines_in_diff(diff_lines, InlineComment(path="main.tf", start_line=10, line=13))
    assert not lines_in_diff(diff_lines, InlineComment(path="main.tf", line=13))


def test_lines_in_diff_on_an_unchanged_file() -> None:
    """Report unsupported suggestion locations rather than trying to annotate unchanged files."""
    assert not lines_in_diff({"main.tf": {1}}, InlineComment(path="other.tf", line=1))


def test_lines_in_diff_treats_a_zero_start_as_single_line() -> None:
    assert lines_in_diff({"main.tf": {5}}, InlineComment(path="main.tf", start_line=0, line=5))
