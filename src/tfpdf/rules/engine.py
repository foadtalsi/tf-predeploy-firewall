"""Exécution du jeu de règles sur un diff analysé.

Port de internal/rules/engine.go et scopecache.go.
"""

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
    """Le résultat d'une passe de scan statique : les découvertes, plus
    l'ensemble des clés d'attributs que le diff .tf de cette PR a réellement
    touchées, par adresse de ressource."""

    findings: list[Finding] = field(default_factory=list)
    #: resource address -> changed attribute keys
    changed_attrs: dict[str, set[ChangedAttrKey]] = field(default_factory=dict)
    #: Ce que l'utilisateur doit savoir du scan lui-même, et qui n'est pas une
    #: découverte : aujourd'hui, les fournisseurs dont le schéma embarqué est
    #: hors de la fourchette épinglée, et pour lesquels on s'est donc tu. Le
    #: moteur n'imprime rien ; l'appelant décide où ça va.
    notes: list[str] = field(default_factory=list)


class ScopeCache:
    """Construit une portée de résolution de références par répertoire et la
    réutilise, pour que scanner vingt fichiers d'un même module lise les .tf de
    ce module une fois plutôt que vingt."""

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
        #: Le contenu de TOUS les fichiers de cette passe, par chemin.
        #:
        #: Les contraintes de version d'un module vivent presque toujours dans
        #: `versions.tf`, c'est-à-dire dans un autre fichier que celui qui porte
        #: la ressource jugée. Sans cette vue d'ensemble, un appelant qui ne
        #: donne pas de `repo_dir` — les tests, et tout usage en bibliothèque —
        #: ne verrait la contrainte d'aucun module.
        self._head_by_path = head_by_path or {}

    def constraints_for(self, path: str, head_content: bytes | None) -> dict[str, str]:
        """Les contraintes de version des fournisseurs qui s'appliquent à `path`.

        Par répertoire, parce que c'est la portée que Terraform donne à
        `required_providers` : un bloc dans `versions.tf` vaut pour tout le
        module, et c'est presque toujours là qu'il vit — pas dans le fichier
        qu'on est en train de scanner.

        `head_content` prime sur la copie du disque, pour la même raison que la
        portée : une PR qui déplace une contrainte doit être jugée sur ce
        qu'elle écrit, pas sur ce qui était là avant.
        """
        directory = str(Path(path).parent)
        if directory in self._constraints_by_directory:
            return self._constraints_by_directory[directory]

        files = self._read_dir(directory) if self.repo_dir else {}
        # Ce que la passe a sous la main prime sur le disque, pour la même
        # raison que la portée : une PR qui déplace une contrainte doit être
        # jugée sur ce qu'elle écrit.
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

    if options.cloud_reader is not None:
        adjust_severity_against_the_cloud(findings)

    notes = drop_findings_the_pinned_provider_contradicts(
        findings, constraints_by_file, knowledge_base
    )

    kept = ignore.apply(findings, inline_by_file, options.global_ignore)
    attach_doc_urls(kept, knowledge_base)

    return Result(findings=kept, changed_attrs=changed_attrs, notes=notes)


#: Les découvertes tirées du SCHÉMA, et elles seules. Ce sont les deux qui
#: disent « le fournisseur accepte ceci / ceci force une destruction » — deux
#: affirmations qui ne valent que pour la version du schéma qu'on porte.
#:
#: Tout le reste juge une valeur écrite dans le fichier : un mot de passe en
#: clair est un mot de passe en clair sur toutes les versions d'AWS, et retirer
#: ces règles-là parce qu'un dépôt épingle un vieux fournisseur serait
#: exactement le mauvais choix.
SCHEMA_DERIVED_RULES = frozenset({"unknown_attribute", "force_new_change"})


def drop_findings_the_pinned_provider_contradicts(
    findings: list[Finding],
    constraints_by_file: dict[str, dict[str, str]],
    knowledge_base: KnowledgeBase | None,
) -> list[str]:
    """Retire les accusations que la version épinglée par le dépôt dément, et
    rend de quoi le dire à l'utilisateur.

    Le cas qui l'a motivé : un dépôt déclare `aws = "~> 3.0"` et écrit
    `vpc = true` sur un `aws_eip`. C'est valide en 3.x — l'attribut n'a disparu
    qu'en 6.x — et le scanner le rapportait en « attribut inconnu », severity
    high, avec un lien vers la documentation 6.59.0. Une accusation confiante et
    fausse, sur précisément ce qui distingue ce produit de `terraform validate`.

    Se taire plutôt que corriger : nous n'avons pas le schéma de la version
    qu'ils utilisent, donc nous n'avons rien à dire de leurs attributs. Prétendre
    le contraire est ce qui vient d'arriver.

    Retire **par fichier**, pas globalement : deux modules d'un même dépôt
    épinglent souvent des fournisseurs différents, et la contrainte de l'un n'a
    rien à dire des ressources de l'autre.
    """
    if knowledge_base is None:
        return []
    version_of = {p.name: p.version for p in knowledge_base.coverage().providers}
    if not version_of:
        return []

    silenced: dict[tuple[str, str, str], None] = {}
    kept: list[Finding] = []
    for finding in findings:
        provider = _provider_the_finding_judges(finding)
        constraint = constraints_by_file.get(finding.file, {}).get(provider, "")
        our_version = version_of.get(provider, "")
        if (
            finding.rule_name in SCHEMA_DERIVED_RULES
            and constraint
            and our_version
            and not providerversion.allows(constraint, our_version)
        ):
            silenced[(provider, constraint, our_version)] = None
            continue
        kept.append(finding)

    if len(kept) != len(findings):
        findings[:] = kept

    return [
        f'{provider} is pinned to "{constraint}" here, and the schema this scanner '
        f"carries is {version}. Attribute and ForceNew findings for {provider} were "
        "dropped rather than judged against a version you do not use — every other "
        "rule still ran."
        for provider, constraint, version in silenced
    ]


def _provider_the_finding_judges(finding: Finding) -> str:
    """Le fournisseur dont cette découverte parle, depuis son adresse de
    ressource. Rend "" pour ce qui n'en désigne aucun — une erreur d'analyse
    porte `-` en guise de ressource."""
    resource_type, _, recognised = type_from_address(finding.resource)
    if not recognised:
        return ""
    return providerversion.provider_of(resource_type)


def adjust_severity_against_the_cloud(findings: list[Finding]) -> None:
    """Réévalue la sévérité des découvertes que l'état réel du compte éclaire.

    Appelée seulement quand l'accès en lecture a été accordé (`--cloud-read-access`) :
    la vérification interroge AWS, et le scanner ne s'authentifie à rien tant
    qu'on ne le lui a pas demandé. C'est la garde qui rend vraie la phrase de la
    page d'accueil, pas une optimisation.

    Placée après la boucle sur les fichiers, parce que `findings` doit être
    complète : au-dessus, aucune règle n'a encore tourné et la liste est vide.

    `cloud_name` et non `resource` : les API cloud ne connaissent pas les
    adresses Terraform. Une découverte dont le nom réel n'a pas pu être établi
    est laissée telle quelle — interroger S3 avec `aws_s3_bucket.backups`
    recevrait « ce compartiment n'existe pas » et ferait baisser la sévérité de
    chaque compartiment du dépôt.

    Un scan sonde le compte une fois au plus : `available_context()` est
    appelée ici, jamais depuis la vérification, et seulement s'il y a quelque
    chose à corroborer.
    """
    adjustable = [
        finding
        for finding in findings
        if finding.rule_name == "s3_force_destroy" and finding.cloud_name
    ]
    if not adjustable:
        # Rien à corroborer : on ne monte même pas la session. Le cas courant
        # sur la plupart des PR, et la raison pour laquelle activer l'option ne
        # coûte rien tant qu'aucune règle concernée ne se déclenche.
        return

    # Importé ici et non en tête de module : en tête, un
    # `tf-predeploy-firewall --version` chargerait boto3 pour rien.
    from ..ruledef import severitycheck

    # Une seule fois, ici, et pas dans la vérification : la sonde est un
    # aller-retour vers STS plus la construction d'un client, et la faire par
    # découverte multipliait les deux par le nombre de compartiments du dépôt.
    # Le résultat est mémorisé dans `severitycheck.AWS_OK`, que la
    # vérification lit.
    if not severitycheck.available_context():
        return

    for finding in adjustable:
        # `Severity(...)` parce que la vérification rend des chaînes nues
        # ("low", "critical") : sans la conversion, le champ contiendrait
        # tantôt une Severity tantôt un str, et le tri comme le seuil de
        # blocage compareraient deux types différents.
        finding.severity = Severity(
            severitycheck.s3_force_destroy_severity_check(
                severity=finding.severity, bucket=finding.cloud_name
            )
        )


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
