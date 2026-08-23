"""Exécution du jeu de règles sur un diff analysé.

Port de internal/rules/engine.go et scopecache.go.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from .. import ignore
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
    """Le résultat d'une passe de scan statique : les découvertes, plus
    l'ensemble des clés d'attributs que le diff .tf de cette PR a réellement
    touchées, par adresse de ressource."""

    findings: list[Finding] = field(default_factory=list)
    #: resource address -> changed attribute keys
    changed_attrs: dict[str, set[ChangedAttrKey]] = field(default_factory=dict)


class ScopeCache:
    """Construit une portée de résolution de références par répertoire et la
    réutilise, pour que scanner vingt fichiers d'un même module lise les .tf de
    ce module une fois plutôt que vingt."""

    __slots__ = ("_scope_by_directory", "repo_dir")

    def __init__(self, repo_dir: str) -> None:
        self.repo_dir = repo_dir
        self._scope_by_directory: dict[str, EvalContext | None] = {}

    def for_file(self, path: str, head_content: bytes | None) -> EvalContext | None:
        """La portée du répertoire contenant `path`. `head_content` est le contenu
        en cours de scan, qui prime sur la copie présente sur le disque.

        Sans `repo_dir` configuré, ceci rend None et chaque référence reste non
        résolue — le comportement d'avant l'existence des portées.
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
        """Charge les fichiers .tf d'un répertoire, sans récursion : Terraform
        cloisonne les locals et les variables à un seul répertoire et ne descend
        pas.
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
    """Analyse chaque fichier modifié et exécute toutes les règles dessus, en
    rendant les découvertes combinées après application des directives
    d'exclusion.

    Une erreur d'analyse sur un fichier est consignée comme sa propre découverte
    informative plutôt que d'interrompre tout le scan.
    """
    options = options or RunOptions()

    findings: list[Finding] = []
    inline_by_file: dict[str, dict[int, set[str]]] = {}
    changed_attrs: dict[str, set[ChangedAttrKey]] = {}

    scopes = ScopeCache(options.repo_dir)

    for changed_file in files:
        # Collect inline ignore directives from the head revision source.
        inline_by_file[changed_file.path] = ignore.parse_comments(changed_file.head_content)

        # The scope is built from the file's own directory, with this file's
        # head content overriding whatever is on disk — on a PR scan the disk
        # holds the checked-out revision, which is what we want, but being
        # explicit keeps the two consistent.
        scope = scopes.for_file(changed_file.path, changed_file.head_content)

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

        base_by_addr: dict[str, Resource] = {}
        if changed_file.base_content is not None:
            # The base revision is parsed without a scope: it exists only to
            # answer "did this attribute's value change", and resolving it
            # against the *head* directory's locals would compare a before
            # value to an after scope.
            try:
                for resource in parse_file(changed_file.path, changed_file.base_content):
                    base_by_addr[resource.address()] = resource
            except HCLParseError:
                pass

        file_input = FileInput(
            path=changed_file.path,
            head_resources=head_resources,
            head_source=changed_file.head_content,
            base_resources=base_by_addr,
        )
        for rule in ruleset:
            findings.extend(rule.check(file_input, knowledge_base))

        for head in head_resources:
            base = base_by_addr.get(head.address())
            if base is not None:
                changed_attrs[head.address()] = changed_attrs_for_resource(head, base)

    kept = ignore.apply(findings, inline_by_file, options.global_ignore)
    attach_doc_urls(kept, knowledge_base)

    return Result(findings=kept, changed_attrs=changed_attrs)


def attach_doc_urls(findings: list[Finding], knowledge_base: KnowledgeBase | None) -> None:
    """Remplit le `doc_url` de chaque découverte à partir de son adresse de
    ressource.

    Fait en une passe sur les résultats plutôt qu'à chacun des deux douzaines
    d'endroits où une découverte est construite : l'adresse identifie déjà le
    type sans ambiguïté, donc faire circuler un lien à travers chaque règle
    ajouterait un paramètre partout pour calculer la même chose. Publique parce
    que les découvertes fondées sur le plan sont produites hors de `run` et
    méritent les mêmes liens.

    Les découvertes dont aucun pack chargé ne couvre le type gardent un
    `doc_url` vide : un lien vers une page qui pourrait ne pas exister est pire
    que pas de lien.
    """
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
