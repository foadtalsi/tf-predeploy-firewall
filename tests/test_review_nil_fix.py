"""Render findings without fixes safely. The historical Go renderer dereferenced missing fixes;
Python deliberately returns an empty suggestion instead.
"""

from __future__ import annotations

from tfpdf.report import (
    Category,
    Finding,
    Severity,
    fix_marker,
    gitlab_suggestion_body,
    review_comment_body,
)


def _no_fix() -> Finding:
    return Finding(
        file="s3.tf",
        line=3,
        category=Category.PUBLIC_EXPOSURE,
        severity=Severity.HIGH,
        resource="aws_s3_bucket.logs",
        message="bucket is public",
    )


def test_review_comment_body_renders_an_empty_suggestion_rather_than_crashing() -> None:
    body = review_comment_body(_no_fix())
    assert "```suggestion\n```\n" in body
    assert "bucket is public" in body


def test_gitlab_suggestion_body_treats_a_missing_fix_as_a_single_line() -> None:
    assert "```suggestion:-0+0\n" in gitlab_suggestion_body(_no_fix())


def test_fix_marker_is_still_stable_without_a_fix() -> None:
    """An empty replacement must still yield stable, finding-specific markers."""
    a = _no_fix()
    b = _no_fix()
    b.resource = "aws_s3_bucket.other"
    assert fix_marker(a) == fix_marker(_no_fix())
    assert fix_marker(a) != fix_marker(b)
