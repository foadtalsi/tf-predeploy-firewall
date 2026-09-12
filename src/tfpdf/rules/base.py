"""Types shared by all rules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..parser import Resource
from ..report.finding import Category, Finding
from ..schema import KnowledgeBase


@dataclass(slots=True)
class FileInput:
    """The contents and context each rule receives for a changed Terraform file."""

    path: str

    #: The resource blocks as they exist after the change.
    head_resources: list[Resource] = field(default_factory=list)

    #: The raw file content the head resources were parsed from. Rules use it
    #: to build `Fix` values, which have to reproduce existing lines byte for
    #: byte. Optional: with it empty, rules simply emit no one-click fixes,
    #: which is why unit tests that construct a FileInput by hand don't have to
    #: supply it.
    head_source: bytes = b""

    #: Maps "type.name" -> resource as it existed before the change, for files
    #: that existed at the base ref. Empty for new files.
    base_resources: dict[str, Resource] = field(default_factory=dict)


class Rule(Protocol):
    """A single risk detector."""

    def check(
        self, file_input: FileInput, knowledge_base: KnowledgeBase | None
    ) -> list[Finding]: ...


@dataclass(slots=True)
class RunOptions:
    """Optional scan-engine settings."""

    #: Categories to suppress across all files.
    global_ignore: list[Category | str] = field(default_factory=list)

    #: The checkout root. When set, each scanned file's whole directory is read
    #: to build a scope for resolving `var.x` and `local.y` — Terraform scopes
    #: those per directory, not per file, so a local declared in locals.tf has
    #: to be visible when scanning rds.tf.
    #:
    #: Leaving it empty disables reference resolution entirely; every rule then
    #: behaves exactly as it did before, skipping non-literal values.
    repo_dir: str = ""

    #: Set when `--cloud-read-access` was given *and* usable credentials were
    #: found — see `tfpdf.cloudread.open_reader`. It is what lets
    #: `engine.adjust_severity_against_the_cloud` run, which is the only place
    #: the scanner asks a cloud API anything.
    #:
    #: None is the default and the whole of the free path: no credentials are
    #: read, no request leaves the runner, and every rule scores exactly as it
    #: always has. Typed loosely to keep `boto3` out of this module's imports.
    cloud_reader: object | None = None


class Options:
    """Compatibility type for integrations calling default_rules(Options())."""


class RuleSet(list["Rule"]):
    """Run multiple rules through one detector interface, such as all credential rules in a pack."""

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        findings: list[Finding] = []
        for rule in self:
            findings.extend(rule.check(file_input, knowledge_base))
        return findings
