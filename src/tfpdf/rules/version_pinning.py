"""Vérification des versions des modules et des fournisseurs."""

from __future__ import annotations

import re

from .. import cloudname
from ..parser import Kind, Resource
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase
from .base import FileInput

#: host), which is the form that takes a separate `version` argument. Local
#: paths (./x, ../x) and everything else are not registry sources.
_REGISTRY_MODULE_SOURCE = re.compile(
    r"^([a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$"
)

#: Pulls the ?ref= out of a git source. Its absence is the problem; `ref=main`
#: is the same problem wearing a name.
_GIT_REF_PARAM = re.compile(r"[?&]ref=([^&]+)")

#: Refs that are branches or moving pointers rather than immutable commits or
#: tags. A 40- or 7-hex-char SHA and anything version-shaped are pinned.
_COMMIT_SHA = re.compile(r"^[0-9a-f]{7,40}$")
_VERSION_TAG = re.compile(r"^v?\d+\.\d+")
_KNOWN_MOBILE = frozenset({"main", "master", "HEAD", "develop", "trunk", "latest"})

#: One `name = { ... }` entry inside a required_providers block, capturing the
#: name and its body.
_REQUIRED_PROVIDER_ENTRY = re.compile(r"([a-z][a-z0-9_-]*)\s*=\s*\{(.*?)\}", re.DOTALL)

#: The `source = "namespace/type"` already written inside such an entry.
_DECLARED_SOURCE = re.compile(r'source\s*=\s*"([^"]+)"')


class UnpinnedVersionRule:
    """Signale les sources de modules et les exigences de fournisseurs qui
    flottent au lieu de nommer une version.

    Une dépendance non épinglée rend un apply non reproductible : le plan que
    quelqu'un a relu et le plan qui s'exécute une heure plus tard peuvent
    différer parce qu'un tiers a déplacé une branche ou publié une release, sans
    aucun commit dans ce dépôt pour l'expliquer. C'est une exposition de chaîne
    d'approvisionnement — qui contrôle cette référence contrôle ce qui s'exécute
    contre votre compte cloud — et c'est aussi le moyen le plus sûr d'obtenir un
    plan que personne ne peut reproduire le jour où il tourne mal.

    Sa place à côté des règles anti-hallucination tient à une raison précise :
    le Terraform généré n'écrit presque jamais de contrainte de version. Un
    modèle à qui l'on demande « un module VPC » émet une source et passe à la
    suite.
    """

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        findings: list[Finding] = []
        for resource in file_input.head_resources:
            if resource.kind is not Kind.MODULE:
                continue
            findings.extend(_check_module_source(file_input.path, resource))
        findings.extend(
            _check_required_providers(file_input.path, file_input.head_source, knowledge_base)
        )
        return findings


def _check_module_source(path: str, resource: Resource) -> list[Finding]:
    source = resource.attributes.get("source")
    if source is None or not source.is_literal or not source.raw_value:
        return []
    value = source.raw_value
    line = source.range.start.line

    def finding(message: str, suggestion: str) -> list[Finding]:
        return [
            Finding(
                file=path,
                line=line,
                category=Category.UNPINNED_VERSION,
                rule_name="unpinned_version",
                severity=Severity.MEDIUM,
                resource=resource.address(),
                cloud_name=cloudname.of(resource),
                message=message,
                suggestion=suggestion,
            )
        ]

    # A local path is versioned by this repository's own history; there is
    # nothing to pin.
    if value.startswith(("./", "../")):
        return []

    if _is_git_source(value):
        match = _GIT_REF_PARAM.search(value)
        if match is None:
            return finding(
                f'module source "{value}" has no ?ref= — every apply takes whatever the '
                "default branch says at that moment, so the plan reviewed here is not the "
                "plan that runs",
                f'source = "{value}?ref=v1.2.3"  # a tag or a commit SHA',
            )
        ref = match.group(1)
        if _COMMIT_SHA.search(ref) or _VERSION_TAG.search(ref):
            return []
        if ref in _KNOWN_MOBILE:
            replaced = value.replace("ref=" + ref, "ref=v1.2.3", 1)
            return finding(
                f"module source pins ?ref={ref}, which is a moving branch — whoever can "
                "push to it decides what runs against your cloud account",
                f'# pin to a tag or commit instead:\nsource = "{replaced}"',
            )
        # An unrecognised ref is more likely a tag we don't recognise the shape
        # of than a branch. Saying nothing beats a false accusation.
        return []

    if _REGISTRY_MODULE_SOURCE.search(value):
        v = resource.attributes.get("version")
        if v is not None and v.is_literal and v.raw_value:
            return []
        return finding(
            f'registry module "{value}" declares no version — Terraform will take the '
            "newest release each time the module is re-initialised",
            'version = "~> 1.2"',
        )
    return []


def _is_git_source(value: str) -> bool:
    return (
        value.startswith(("git::", "git@", "hg::"))
        or "github.com/" in value
        or "gitlab.com/" in value
    )


def _check_required_providers(
    path: str, source: bytes, knowledge_base: KnowledgeBase | None
) -> list[Finding]:
    """Signale les fournisseurs déclarés sans contrainte de version.

    Ceci lit le texte source plutôt que les ressources analysées, parce que
    `terraform { required_providers { … } }` est un bloc imbriqué dans un bloc
    qui n'est pas une ressource, et que le parseur ne modélise délibérément pas
    — ce n'est pas de l'infrastructure. Faire correspondre le texte du bloc est
    assez étroit pour être sûr, et évite de faire grossir le parseur pour une
    seule règle.
    """
    if not source:
        return []
    text = source.decode("utf-8", errors="replace")
    found = _required_providers_body(text)
    if found is None:
        return []
    body, start_line = found

    findings: list[Finding] = []
    for match in _REQUIRED_PROVIDER_ENTRY.finditer(body):
        name = match.group(1)
        entry = match.group(2)
        if "version" in entry:
            continue
        findings.append(
            Finding(
                file=path,
                line=start_line + body[: match.start()].count("\n"),
                category=Category.UNPINNED_VERSION,
                rule_name="unpinned_version",
                severity=Severity.MEDIUM,
                resource="provider." + name,
                message=(
                    f'provider "{name}" declares no version constraint — a new major '
                    "release of it can change or break this configuration with no commit "
                    "here to explain why"
                ),
                suggestion=_pin_suggestion(name, entry, knowledge_base),
            )
        )
    return findings


def _pin_suggestion(name: str, entry: str, knowledge_base: KnowledgeBase | None) -> str:
    """Le bloc à coller pour épingler ce fournisseur, ou "" quand on ne sait pas.

    Deux inventions vivaient ici, et la première était grave.

    **L'adresse.** Le bloc écrivait `source = "hashicorp/{name}"` sans
    condition. Sur un dépôt qui déclare son propre fournisseur — Rootly publie
    `rootlyhq/rootly`, et l'écrit dans l'entrée juste au-dessus — la suggestion
    remplaçait l'adresse correcte par une adresse qui n'existe pas. Dans un bloc
    ```suggestion de GitHub, c'est-à-dire derrière un bouton « Commit
    suggestion ». Envoyer cela à l'équipe qui publie ce fournisseur est le pire
    résultat possible d'un outil qui se vend sur l'exactitude.

    Une adresse déclarée est donc reprise telle quelle, et **aucune n'est jamais
    écrite si elle n'était pas déjà là**. Terraform résout un `source` absent en
    `hashicorp/<nom>` de toute façon ; l'écrire nous-mêmes n'ajouterait rien et
    ferait passer une convention pour une vérification.

    **La version.** `~> 5.0` était une constante, vraie d'aucun fournisseur en
    particulier. Elle vient maintenant de la base de connaissances — la seule
    chose ici qui sache réellement quelle version d'un fournisseur existe. Pour
    un fournisseur qu'elle ne couvre pas, il n'y a pas de suggestion du tout :
    la découverte reste, et elle dit ce qui manque sans prétendre le remplir.
    """
    if knowledge_base is None:
        return ""
    major = _known_major(name, entry, knowledge_base)
    if major is None:
        return ""

    lines = [f"{name} = {{"]
    declared = _DECLARED_SOURCE.search(entry)
    if declared is not None:
        lines.append(f'  source  = "{declared.group(1)}"')
    lines.append(f'  version = "~> {major}.0"')
    lines.append("}")
    return "\n".join(lines)


def _known_major(name: str, entry: str, knowledge_base: KnowledgeBase) -> str | None:
    """Le numéro majeur que la base de connaissances porte pour ce fournisseur,
    ou None.

    L'adresse décide, pas le nom local : `aws = { source = "someone/aws" }` est
    un autre fournisseur que celui dont nous avons le schéma, et lui proposer
    notre numéro de version serait la même erreur d'un cran plus discrète. Un
    `source` absent vaut `hashicorp/<nom>`, ce que Terraform fait lui-même.
    """
    declared = _DECLARED_SOURCE.search(entry)
    address = declared.group(1) if declared is not None else f"hashicorp/{name}"
    namespace, _, type_ = address.rpartition("/")
    if namespace.lower() != "hashicorp":
        return None
    for provider in knowledge_base.coverage().providers:
        if provider.name == type_:
            return provider.version.split(".")[0] or None
    return None


def _required_providers_body(source: str) -> tuple[str, int] | None:
    """Le texte à l'intérieur de `required_providers { … }` et la ligne où il
    commence, par appariement d'accolades depuis le mot-clé."""
    index = source.find("required_providers")
    if index < 0:
        return None
    open_idx = source.find("{", index)
    if open_idx < 0:
        return None

    depth = 0
    for i in range(open_idx, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[open_idx + 1 : i], source[:open_idx].count("\n") + 1
    return None  # unbalanced; the HCL parser will report it
