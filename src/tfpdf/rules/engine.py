"""Run rules against parsed file changes and cache directory scopes."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .. import ignore, providerversion
from ..hcl import EvalContext, HCLParseError
from ..parser import Resource, build_scope, parse_file, parse_file_with_context, type_from_address
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase
from .base import FileInput, Rule, RunOptions
from .changedattrs import ChangedAttrKey, changed_attrs_for_resource

if TYPE_CHECKING:
    from ..diff import ChangedFile


@dataclass(slots=True)
class Result:
    """Static findings plus changed attribute keys grouped by resource address."""

    findings: list[Finding] = field(default_factory=list)
    #: resource address -> changed attribute keys
    changed_attrs: dict[str, set[ChangedAttrKey]] = field(default_factory=dict)
    # Non-finding scan warnings, including schema versions outside provider constraints. The
    # caller decides where to display them.
    notes: list[str] = field(default_factory=list)


class ScopeCache:
    """Cache reference-resolution scopes per directory so files in one module share a single read."""

    __slots__ = (
        "_constraints_by_directory",
        "_head_by_path",
        "_scope_by_directory",
        "repo_dir",
    )

    def __init__(self, repo_dir: str, head_by_path: dict[str, bytes] | None = None) -> None:
        self.repo_dir = repo_dir
        self._scope_by_directory: dict[str, EvalContext | None] = {}
        self._constraints_by_directory: dict[str, dict[str, str]] = {}
        # All scanned files, indexed by path, so constraints in sibling versions.tf files work
        # even without repo_dir.
        self._head_by_path = head_by_path or {}

    def constraints_for(self, path: str, head_content: bytes | None) -> dict[str, str]:
        """Resolve directory-scoped provider constraints, preferring scanned contents over disk."""
        directory = str(Path(path).parent)
        if directory in self._constraints_by_directory:
            return self._constraints_by_directory[directory]

        files = self._read_dir(directory) if self.repo_dir else {}
        # Scanned contents override disk so constraints reflect the revision under review.
        for other, content in self._head_by_path.items():
            if str(Path(other).parent) == directory:
                files[other] = content
        if head_content is not None:
            files[path] = head_content

        found: dict[str, str] = {}
        for _, source in sorted(files.items()):
            for name, constraint in providerversion.constraints_in(source).items():
                found.setdefault(name, constraint)
        self._constraints_by_directory[directory] = found
        return found

    def for_file(self, path: str, head_content: bytes | None) -> EvalContext | None:
        """Build and cache a directory's scope, preferring supplied contents over disk. Return None
        without repo_dir.
        """
        if not self.repo_dir:
            return None

        directory = str(Path(path).parent)
        if directory in self._scope_by_directory:
            return self._scope_by_directory[directory]

        files = self._read_dir(directory)
        if head_content is not None:
            files[path] = head_content
        scope = build_scope(files)
        self._scope_by_directory[directory] = scope
        return scope

    def _read_dir(self, directory: str) -> dict[str, bytes]:
        """Read only this directory's Terraform files; variables and locals do not cross module
        directories.
        """
        sources_by_path: dict[str, bytes] = {}

        try:
            repository_root = Path(self.repo_dir).resolve()
            target_directory = (Path(self.repo_dir) / directory).resolve()
        except OSError:
            return sources_by_path

        # Refuse to read outside the repository. `directory` comes from a git
        # path so it should already be clean, but a scanner that reads
        # arbitrary files because of a crafted path in someone's PR is not a
        # trade worth taking.
        if target_directory != repository_root and repository_root not in target_directory.parents:
            return sources_by_path

        try:
            entries = sorted(target_directory.iterdir())
        except OSError:
            # A directory we can't read (deleted in this PR, permissions) just
            # means no scope for it, not a failed scan.
            return sources_by_path

        for entry in entries:
            if entry.is_dir() or entry.suffix != ".tf":
                continue
            try:
                sources_by_path[str(Path(directory) / entry.name)] = entry.read_bytes()
            except OSError:
                continue
        return sources_by_path


def run(
    files: list[ChangedFile],
    knowledge_base: KnowledgeBase | None,
    ruleset: list[Rule],
    options: RunOptions | None = None,
) -> Result:
    """Scan files and apply exclusions. Report HCL errors as findings while continuing with other
    files.
    """
    options = options or RunOptions()

    findings: list[Finding] = []
    inline_by_file: dict[str, dict[int, set[str]]] = {}
    changed_attrs: dict[str, set[ChangedAttrKey]] = {}
    constraints_by_file: dict[str, dict[str, str]] = {}

    scopes = ScopeCache(
        options.repo_dir,
        {f.path: f.head_content for f in files},
    )

    for changed_file in files:
        # Collect inline ignore directives from the head revision source.
        inline_by_file[changed_file.path] = ignore.parse_comments(changed_file.head_content)

        # The scope is built from the file's own directory, with this file's
        # head content overriding whatever is on disk — on a PR scan the disk
        # holds the checked-out revision, which is what we want, but being
        # explicit keeps the two consistent.
        scope = scopes.for_file(changed_file.path, changed_file.head_content)
        constraints_by_file[changed_file.path] = scopes.constraints_for(
            changed_file.path, changed_file.head_content
        )

        try:
            head_resources = parse_file_with_context(
                changed_file.path, changed_file.head_content, scope
            )
        except HCLParseError as parse_error:
            findings.append(
                Finding(
                    file=changed_file.path,
                    line=1,
                    category=Category.UNKNOWN_ATTRIBUTE,
                    severity=Severity.MEDIUM,
                    resource="-",
                    message=f"could not parse file as HCL: {parse_error}",
                )
            )
            continue

        base_resources_by_address: dict[str, Resource] = {}
        if changed_file.base_content is not None:
            # The base revision is parsed without a scope: it exists only to
            # answer "did this attribute's value change", and resolving it
            # against the *head* directory's locals would compare a before
            # value to an after scope.
            try:
                for resource in parse_file(changed_file.path, changed_file.base_content):
                    base_resources_by_address[resource.address()] = resource
            except HCLParseError:
                pass

        file_input = FileInput(
            path=changed_file.path,
            head_resources=head_resources,
            head_source=changed_file.head_content,
            base_resources=base_resources_by_address,
        )
        for rule in ruleset:
            findings.extend(rule.check(file_input, knowledge_base))

        for head_resource in head_resources:
            base_resource = base_resources_by_address.get(head_resource.address())
            if base_resource is not None:
                changed_attrs[head_resource.address()] = changed_attrs_for_resource(
                    head_resource, base_resource
                )

    if options.cloud_reader is not None:
        adjust_severity_against_the_cloud(findings)

    notes = drop_findings_the_pinned_provider_contradicts(
        findings, constraints_by_file, knowledge_base
    )

    retained_findings = ignore.apply(findings, inline_by_file, options.global_ignore)
    attach_doc_urls(retained_findings, knowledge_base)

    return Result(findings=retained_findings, changed_attrs=changed_attrs, notes=notes)


# Only schema-derived checks depend on provider version. Value checks must still run with older
# provider pins.
SCHEMA_DERIVED_RULES = frozenset({"unknown_attribute", "force_new_change"})


def drop_findings_the_pinned_provider_contradicts(
    findings: list[Finding],
    constraints_by_file: dict[str, dict[str, str]],
    knowledge_base: KnowledgeBase | None,
) -> list[str]:
    """Remove schema claims incompatible with pinned provider versions and return explanatory
    warnings.
    """
    if knowledge_base is None:
        return []
    versions_by_provider = {p.name: p.version for p in knowledge_base.coverage().providers}
    if not versions_by_provider:
        return []

    silenced: dict[tuple[str, str, str], None] = {}
    retained_findings: list[Finding] = []
    for finding in findings:
        provider = _provider_the_finding_judges(finding)
        constraint = constraints_by_file.get(finding.file, {}).get(provider, "")
        schema_version = versions_by_provider.get(provider, "")
        if (
            finding.rule_name in SCHEMA_DERIVED_RULES
            and constraint
            and schema_version
            and not providerversion.allows(constraint, schema_version)
        ):
            silenced[(provider, constraint, schema_version)] = None
            continue
        retained_findings.append(finding)

    if len(retained_findings) != len(findings):
        findings[:] = retained_findings

    return [
        f'{provider} is pinned to "{constraint}" here, and the schema this scanner '
        f"carries is {version}. Attribute and ForceNew findings for {provider} were "
        "dropped rather than judged against a version you do not use — every other "
        "rule still ran."
        for provider, constraint, version in silenced
    ]


def _provider_the_finding_judges(finding: Finding) -> str:
    """Resolve the finding's provider from its resource address, or return an empty string for
    findings without one.
    """
    resource_type, _, recognised = type_from_address(finding.resource)
    if not recognised:
        return ""
    return providerversion.provider_of(resource_type)


def adjust_severity_against_the_cloud(findings: list[Finding]) -> None:
    """Adjust eligible findings using optional read-only cloud observations."""
    adjustable = [
        finding
        for finding in findings
        if finding.rule_name == "s3_force_destroy" and finding.cloud_name
    ]
    if not adjustable:
        # Do not open a cloud session when no finding can use it.
        return

    # Import lazily so commands such as --version do not load boto3.
    from ..ruledef import severitycheck

    # Probe once before the loop; checks reuse AWS_OK rather than querying STS per finding.
    if not severitycheck.available_context():
        return

    for finding in adjustable:
        # Convert returned strings to Severity to keep sorting and threshold comparisons
        # consistent.
        finding.severity = Severity(
            severitycheck.s3_force_destroy_severity_check(
                severity=finding.severity, bucket=finding.cloud_name
            )
        )


def attach_doc_urls(findings: list[Finding], knowledge_base: KnowledgeBase | None) -> None:
    """Attach provider documentation URLs based on resource addresses."""
    if knowledge_base is None:
        return
    url_by_resource: dict[str, str] = {}
    for finding in findings:
        if finding.doc_url or not finding.resource:
            continue
        url = url_by_resource.get(finding.resource)
        if url is None:
            url = ""
            resource_type, is_data_source, recognised = type_from_address(finding.resource)
            if recognised:
                url = knowledge_base.doc_url(resource_type, is_data_source)
            url_by_resource[finding.resource] = url
        finding.doc_url = url
