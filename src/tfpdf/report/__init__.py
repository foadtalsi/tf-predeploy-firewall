"""Les découvertes produites par le moteur de règles, et chaque forme sous laquelle elles sont
rendues."""

from .codequality import SEVERITY_TO_CODE_QUALITY, render_code_quality
from .finding import Category, Finding, Fix, Severity
from .markdown import (
    MARKER,
    SEVERITY_EMOJI,
    highest_severity,
    render_markdown,
    resource_cell,
)
from .review import (
    FIX_MARKER_PREFIX,
    fix_marker,
    gitlab_suggestion_body,
    has_fix_marker,
    review_comment_body,
)
from .ruledocs import (
    CUSTOM_CATEGORY_PREFIX,
    DOCS_BASE_URL,
    RuleHelp,
    category_display,
    category_title,
    lookup_rule_help,
    render_rule_docs,
    rule_help_uri,
)
from .sarif import (
    SARIF_RULES,
    SEVERITY_TO_SARIF_LEVEL,
    SarifRule,
    described_rules,
    render_sarif,
    set_tool_version,
)
from .terminal import render_terminal, wants_color

__all__ = [
    "CUSTOM_CATEGORY_PREFIX",
    "DOCS_BASE_URL",
    "FIX_MARKER_PREFIX",
    "MARKER",
    "SARIF_RULES",
    "SEVERITY_EMOJI",
    "SEVERITY_TO_CODE_QUALITY",
    "SEVERITY_TO_SARIF_LEVEL",
    "Category",
    "Finding",
    "Fix",
    "RuleHelp",
    "SarifRule",
    "Severity",
    "category_display",
    "category_title",
    "described_rules",
    "fix_marker",
    "gitlab_suggestion_body",
    "has_fix_marker",
    "highest_severity",
    "lookup_rule_help",
    "render_code_quality",
    "render_markdown",
    "render_rule_docs",
    "render_sarif",
    "render_terminal",
    "resource_cell",
    "review_comment_body",
    "rule_help_uri",
    "set_tool_version",
    "wants_color",
]
