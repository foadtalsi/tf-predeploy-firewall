"""Rule-help lookup tests. Full generated-document comparisons live in test_report_parity.py."""

from __future__ import annotations

from tfpdf.report import (
    SARIF_RULES,
    Category,
    category_display,
    described_rules,
    lookup_rule_help,
)


def test_every_rule_is_documented() -> None:
    """Every shipped category needs an explanation."""
    for r in SARIF_RULES:
        h = lookup_rule_help(r.id)
        assert h is not None, f"category {r.id!r} has a SARIF rule but no docs entry"
        assert h.full_description, f"category {r.id!r} has an empty description"
        assert h.markdown, f"category {r.id!r} has empty help"
        # Every rule must say how to disagree with it, or the only available
        # response to a false positive is to uninstall the tool.
        assert any(
            token in h.markdown for token in ("tf-firewall-ignore", "ignore_paths", "threshold")
        ), f"category {r.id!r} never explains how to suppress or tune it"


def test_described_rules_carry_help_and_uri() -> None:
    for r in described_rules():
        assert r.help_uri, f"rule {r.id!r} has no helpUri"
        assert r.help_uri.endswith("#" + str(r.id)), (
            f"rule {r.id!r} helpUri must anchor on the category id"
        )
        assert r.help is not None and r.help.markdown, (
            f"rule {r.id!r} has no rendered help — the alert page would be a bare message"
        )


def test_described_rules_does_not_mutate_the_catalogue() -> None:
    """Rendering must not mutate the shared rule catalogue across reports."""
    described_rules()
    for r in SARIF_RULES:
        assert not r.help_uri
        assert r.help is None
        assert r.full_description is None


def test_category_display_names_a_custom_rule() -> None:
    """Give custom categories readable labels even without built-in help entries."""
    assert category_display("custom:no-iam-users") == "Custom rule: no-iam-users"
    # The label comes from the pack's `title`, never from a second copy in
    # code: a renamed rule reading one way in the PR comment and another on the
    # alert page it links to is exactly what that avoids.
    assert category_display(Category.TUTORIAL_PATTERN) == "Tutorial-copy pattern"
    # An unrecognized, non-custom category renders as itself rather than blank.
    assert category_display("something_else") == "something_else"
