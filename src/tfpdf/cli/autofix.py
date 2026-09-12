"""Request Bedrock fixes; write local files only after the user accepts the diff."""

from __future__ import annotations

import argparse
import sys
from difflib import SequenceMatcher, unified_diff
from pathlib import Path

from .. import parser
from .._httpjson import HTTPError, send_json
from ..hcl.diagnostics import HCLParseError
from ..report.finding import Finding, Fix, Severity
from . import terraformscan


def request_fix(findings: list[Finding], source: bytes, key: str, api_base: str) -> str:
    """Send a file and its findings to the server, which checks Growth access."""
    response = send_json(
        "POST",
        api_base.rstrip("/") + "/v1/autofix",
        {"Authorization": "Bearer " + key},
        {
            "rule_id": ", ".join(f.rule_name or str(f.category) for f in findings),
            "severity": str(findings[0].severity),
            "message": "\n".join(f"Line {f.line}: {f.message}" for f in findings),
            "file_path": findings[0].file,
            "code_to_fix": source.decode("utf-8"),
        },
        want_response=True,
    )
    code = response.get("fixed_code") if isinstance(response, dict) else None
    if not isinstance(code, str) or not code.strip() or "```" in code:
        raise ValueError("empty correction or Markdown instead of Terraform")
    parser.parse_file(findings[0].file, code.encode())
    return code


def replacement(source: str, corrected: str) -> Fix | None:
    """Reduce the corrected file to a line range suitable for a GitHub suggestion."""
    before, after = source.splitlines(), corrected.splitlines()
    changes = [
        op
        for op in SequenceMatcher(None, before, after, autojunk=False).get_opcodes()
        if op[0] != "equal"
    ]
    if not changes:
        return None
    _, start, _, new_start, _ = changes[0]
    _, _, end, _, new_end = changes[-1]
    # GitHub insertions must anchor to an existing line.
    if start == end:
        if start:
            start -= 1
            new_start -= 1
        else:
            end = 1
            new_end += 1
    return Fix(
        start + 1,
        end,
        after[new_start:new_end],
        "Bedrock proposal: review before accepting, then run the scan again.",
    )


def accept_local(path: Path, source: bytes, corrected: str) -> None:
    """Show the diff and write it after confirmation, provided the source has not changed."""
    print(
        "".join(
            unified_diff(
                source.decode().splitlines(True),
                corrected.splitlines(True),
                fromfile=str(path),
                tofile=str(path),
            )
        ),
        end="",
    )
    if not sys.stdin.isatty():
        print("Auto-fix: preview only; run in a terminal to accept a correction.", file=sys.stderr)
        return
    if input("Apply this correction? [y/N] ").strip().lower() not in {"y", "yes", "o", "oui"}:
        return
    if path.is_symlink() or path.read_bytes() != source:
        raise ValueError("file differs from the scanned version; scan it again before applying")
    path.write_bytes(corrected.encode())
    print("Correction applied. Review, stage if needed, and run the scan again.", file=sys.stderr)


def propose(args: argparse.Namespace, findings: list[Finding], post_comment: bool) -> None:
    """Propose one fix per file. Pull request fixes are accepted through the code host."""
    if not args.license_key:
        print("Auto-fix requires an active Growth license key.", file=sys.stderr)
        return
    sources = {
        f.path: f.head_content
        for f in terraformscan.changed_terraform(
            args.repo_dir,
            terraformscan.Mode(
                args.staged, args.uncommitted, args.full_repo_scan, args.base_ref, args.head_ref
            ),
        )
    }
    grouped: dict[str, list[Finding]] = {}
    for finding in sorted(findings, key=lambda f: list(Severity).index(f.severity), reverse=True):
        if not finding.waived and finding.file in sources:
            grouped.setdefault(finding.file, []).append(finding)
    for filename, file_findings in grouped.items():
        try:
            path = Path(args.repo_dir) / filename
            if (
                not path.resolve().is_relative_to(Path(args.repo_dir).resolve())
                or path.is_symlink()
            ):
                raise ValueError("file is outside the repository or is a symlink")
            source = sources[filename]
            corrected = request_fix(file_findings, source, args.license_key, args.license_api_base)
            fix = replacement(source.decode(), corrected)
            if fix is None:
                continue
            for finding in file_findings:
                finding.fix = None
            file_findings[0].fix = fix
            file_findings[0].suggestion = corrected
            if not post_comment:
                accept_local(path, source, corrected)
        except (HTTPError, OSError, ValueError, EOFError, HCLParseError) as exc:
            print(f"Auto-fix unavailable for {filename}: {exc}", file=sys.stderr)
            break
