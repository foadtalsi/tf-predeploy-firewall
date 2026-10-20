"""Findings for files the scanner could not analyse.

A file the scanner cannot read is not a file without risk. Reporting nothing for it would let one
syntax error, or one construct this parser rejects, hide every other problem in the file, so each
of these is a finding of its own. Their definitions in ruledef/rules.py carry the same severities.
"""

from __future__ import annotations

from ..hcl import HCLParseError
from ..report.finding import Category, Finding, Severity

#: Blocks at the default threshold. A file Terraform itself rejects cannot be applied, so blocking
#: it costs nothing; a file Terraform accepts and this parser rejects is a parser defect, and
#: blocking is what makes it visible instead of silently unscanned.
UNPARSABLE_FILE_SEVERITY = Severity.HIGH

#: The head revision was analysed; only the comparison with the base revision, which ForceNew
#: detection needs, is missing.
UNPARSABLE_BASE_FILE_SEVERITY = Severity.LOW

#: Reported without blocking at the default threshold: a repository of generated .tf.json files
#: would otherwise be blocked on every pull request with nothing its authors could fix.
UNSUPPORTED_FILE_FORMAT_SEVERITY = Severity.MEDIUM


def error_line(error: Exception) -> int:
    """Return the line of the first located parse error, or 1 when the error has no position."""
    if isinstance(error, HCLParseError):
        for diagnostic in error.diags:
            if diagnostic.subject is not None and diagnostic.subject.start.line > 0:
                return diagnostic.subject.start.line
    return 1


def unparsable_file(path: str, error: Exception, file_format: str = "HCL") -> Finding:
    """Report a file whose head revision could not be parsed, so that no rule ran on it."""
    return Finding(
        file=path,
        line=error_line(error),
        category=Category.INCOMPLETE_ANALYSIS,
        rule_name="unparsable_file",
        severity=UNPARSABLE_FILE_SEVERITY,
        resource="-",
        message=(
            f"could not parse file as {file_format}: {error} — no rule ran on this file, so "
            "nothing in it was checked"
        ),
    )


def unparsable_base_file(path: str, error: Exception) -> Finding:
    """Report a file whose base revision could not be parsed, so that ForceNew changes in it went
    unchecked.
    """
    return Finding(
        file=path,
        line=1,
        category=Category.INCOMPLETE_ANALYSIS,
        rule_name="unparsable_base_file",
        severity=UNPARSABLE_BASE_FILE_SEVERITY,
        resource="-",
        message=(
            f"could not parse the previous version of this file as HCL: {error} — the new "
            "version was checked, but changes that force a resource to be replaced were not"
        ),
    )


def unsupported_file_format(path: str) -> Finding:
    """Report a Terraform JSON file, which this scanner does not analyse."""
    return Finding(
        file=path,
        line=1,
        category=Category.INCOMPLETE_ANALYSIS,
        rule_name="unsupported_file_format",
        severity=UNSUPPORTED_FILE_FORMAT_SEVERITY,
        resource="-",
        message=(
            "Terraform JSON syntax (.tf.json) is not analysed by this scanner — nothing in "
            "this file was checked"
        ),
    )
