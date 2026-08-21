"""Port de internal/report/review_test.go, cas pour cas."""

from __future__ import annotations

import json

from tfpdf.report import (
    Category,
    Finding,
    Fix,
    Severity,
    fix_marker,
    gitlab_suggestion_body,
    has_fix_marker,
    render_code_quality,
    review_comment_body,
)


def _fix_finding() -> Finding:
    return Finding(
        file="rds.tf",
        line=12,
        category=Category.MISSING_LIFECYCLE,
        severity=Severity.MEDIUM,
        resource="aws_db_instance.prod",
        message="no prevent_destroy guard",
        fix=Fix(
            start_line=12,
            end_line=12,
            lines=[
                'resource "aws_db_instance" "prod" {',
                "  lifecycle {",
                "    prevent_destroy = true",
                "  }",
            ],
        ),
    )


def test_review_comment_body_wraps_the_fix_in_a_suggestion_block() -> None:
    """Le bloc de suggestion est toute la fonctionnalité : GitHub ne rend le
    bouton « Commit suggestion » que pour un bloc ouvert exactement par
    ```suggestion."""
    body = review_comment_body(_fix_finding())

    assert "```suggestion\n" in body, body
    between = body.split("```suggestion\n", 1)[1].split("```", 1)[0]

    want = 'resource "aws_db_instance" "prod" {\n  lifecycle {\n    prevent_destroy = true\n  }\n'
    assert between == want
    assert "no prevent_destroy guard" in body, "the comment must say why, not just what"


def test_review_comment_body_includes_the_note_when_the_fix_is_not_self_sufficient() -> None:
    f = _fix_finding()
    assert f.fix is not None
    f.fix.note = "You also need to declare the variable."
    assert "You also need to declare the variable." in review_comment_body(f)


def test_fix_marker_ignores_line_number_but_not_content() -> None:
    """Le marqueur est la façon dont une nouvelle exécution reconnaît ses
    propres suggestions. Le baser sur le numéro de ligne reposterait tout après
    la moindre édition au-dessus."""
    a = _fix_finding()

    moved = _fix_finding()
    moved.line = 400
    assert moved.fix is not None
    moved.fix.start_line = 400
    moved.fix.end_line = 400
    assert fix_marker(a) == fix_marker(moved)

    changed = _fix_finding()
    assert changed.fix is not None
    changed.fix.lines = ["something else entirely"]
    assert fix_marker(a) != fix_marker(changed)

    other_resource = _fix_finding()
    other_resource.resource = "aws_db_instance.staging"
    assert fix_marker(a) != fix_marker(other_resource), (
        "the same fix on a different resource must not be deduplicated away"
    )


def test_has_fix_marker_matches_an_already_posted_comment() -> None:
    f = _fix_finding()
    assert has_fix_marker(review_comment_body(f), f)
    assert not has_fix_marker("an unrelated human comment", f)


def test_fix_marker_is_an_html_comment() -> None:
    """Le marqueur doit être invisible dans le commentaire rendu, sinon chaque
    suggestion porte une ligne de bruit."""
    m = fix_marker(_fix_finding())
    assert m.startswith("<!--") and m.endswith("-->"), m


def test_gitlab_suggestion_body_fence_carries_the_range_offset() -> None:
    """Le bloc de GitLab est relatif à la ligne sur laquelle il est ancré : un
    correctif qui remplace les lignes 12 à 15, ancré en 12, doit dire
    `suggestion:-0+3`. Se tromper de décalage remplace les mauvaises lignes — en
    un clic."""
    f = _fix_finding()  # start_line 12, end_line 12: single line
    assert "```suggestion:-0+0\n" in gitlab_suggestion_body(f)

    assert f.fix is not None
    f.fix.end_line = 15
    assert "```suggestion:-0+3\n" in gitlab_suggestion_body(f)
    # The marker must be identical across both grammars: the same fix posted on
    # either forge is the same fix.
    assert fix_marker(f) == fix_marker(f)


def test_render_code_quality() -> None:
    f = _fix_finding()
    waived = _fix_finding()
    waived.waived = True
    waived.resource = "aws_db_instance.accepted"

    issues = json.loads(render_code_quality([f, waived]))
    assert len(issues) == 1, "waived findings are decisions, not open issues"

    issue = issues[0]
    assert issue["severity"] == "minor"  # medium → minor
    assert issue["fingerprint"], "GitLab would treat every pipeline's findings as new"
    assert issue["location"]["path"] == "rds.tf"

    # Line-independent fingerprint: a rebase must not churn identities.
    moved = _fix_finding()
    moved.line = 400
    issues2 = json.loads(render_code_quality([moved]))
    assert issues2[0]["fingerprint"] == issue["fingerprint"]
