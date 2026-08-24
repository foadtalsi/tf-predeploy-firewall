"""Les détecteurs compilés — les vérifications qu'un matcher déclaratif ne peut
pas exprimer.

Porte internal/rules/rule_unknown_attr.go, rule_forcenew.go,
rule_missing_lifecycle.go, rule_unpinned.go, rule_iam_wildcard.go et
rule_cost_static.go.

Chacun possède son propre parcours parce qu'il lui faut quelque chose dont le
format de règles n'a pas le vocabulaire : une recherche dans le schéma du
fournisseur, une comparaison avec la révision de base, ou un balayage à
accolades appariées de la source brute. Les règles déclarent toujours leur
identité, leur sévérité, leur formulation et leur documentation dans
`ruledef/rules.py` — seul le parcours est du code.
"""

from __future__ import annotations

import re

from .. import cloudname
from ..parser import Attribute, Kind, NestedBlock, Resource
from ..report.finding import Category, Finding, Fix, Severity
from ..schema import KnowledgeBase, PricingSpec
from .base import FileInput
from .fix import LineEdit, insert_into_block, replace_attr_line


def _as_fix(edit: LineEdit | None) -> Fix | None:
    """Élève une édition de ligne résolue en Fix, en laissant passer None.

    Les aides d'édition rendent None dès que la source ne ressemblait pas à ce
    qu'elles supposaient, et tous les appelants d'ici réagissent pareil :
    émettre la découverte avec sa seule suggestion en langage humain.
    """
    if edit is None:
        return None
    return Fix(start_line=edit.start, end_line=edit.end, lines=edit.lines)


# --- unknown attributes ---------------------------------------------------


class UnknownAttributeRule:
    """Signale les attributs absents du schéma connu pour un type de ressource
    — signature courante d'une hallucination d'IA : un attribut qui « sonne
    juste » mais n'existe pas.

    Seuls les types couverts par un pack de règles chargé sont vérifiés ; les
    types non couverts sont sautés, pour éviter les faux positifs sur des
    attributs réels mais non décrits.
    """

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        if kb is None:
            return []
        findings: list[Finding] = []

        for res in in_.head_resources:
            # Module inputs are someone else's variables and data sources are
            # read paths — neither has an entry in a provider resource pack, so
            # there is nothing to validate an argument name against.
            if res.kind is not Kind.RESOURCE:
                continue
            res_schema = kb.resource_schema(res.type)
            if res_schema is None:
                continue

            allowed_top = set(res_schema.top_level)
            for name in sorted(res.attributes):
                if name in allowed_top:
                    continue
                findings.append(
                    Finding(
                        file=in_.path,
                        line=res.attributes[name].range.start.line,
                        category=Category.UNKNOWN_ATTRIBUTE,
                        rule_name="unknown_attribute",
                        severity=Severity.HIGH,
                        resource=res.address(),
                        cloud_name=cloudname.of(res),
                        message=(
                            f'attribute "{name}" is not a known argument of {res.type} — '
                            "likely hallucinated or deprecated; verify against the provider docs"
                        ),
                    )
                )

            # Only validate block types explicitly listed in the schema;
            # uncurated block types (dynamic, provisioner, …) are skipped.
            for blk in res.blocks:
                allowed_attrs = res_schema.nested_blocks.get(blk.type)
                if allowed_attrs is None:
                    continue
                allowed_blk = set(allowed_attrs)
                for name in sorted(blk.attributes):
                    if name in allowed_blk:
                        continue
                    findings.append(
                        Finding(
                            file=in_.path,
                            line=blk.attributes[name].range.start.line,
                            category=Category.UNKNOWN_ATTRIBUTE,
                            rule_name="unknown_attribute",
                            severity=Severity.HIGH,
                            resource=res.address(),
                            cloud_name=cloudname.of(res),
                            message=(
                                f'attribute "{name}" inside {blk.type} block is not a known '
                                "argument — likely hallucinated or deprecated; verify against "
                                "the provider docs"
                            ),
                        )
                    )

        return findings


# --- ForceNew -------------------------------------------------------------


class ForceNewChangeRule:
    """Signale les modifications d'attributs connus comme ForceNew dans le
    schéma du fournisseur, sur une ressource qui existait déjà avant ce
    changement.

    Sans plan ni état, on ne peut pas savoir ce qui est réellement déployé, mais
    « cet attribut a changé sur une adresse de ressource préexistante » est un
    indicateur fiable : l'appliquer détruira et recréera la ressource.
    """

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        if kb is None:
            return []
        findings: list[Finding] = []

        for res in in_.head_resources:
            # Only a managed resource is destroyed and recreated. A module call
            # has no ForceNew surface of its own, and a data source is never
            # replaced because it is never created.
            if res.kind is not Kind.RESOURCE:
                continue
            base = in_.base_resources.get(res.address())
            if base is None:
                continue

            spec = kb.force_new(res.type)
            if spec is None:
                continue

            severity = Severity.CRITICAL if kb.is_critical(res.type) else Severity.HIGH

            for attr_name in spec.top_level:
                f = _compare_attr(
                    in_.path,
                    res.address(),
                    res.type,
                    attr_name,
                    "",
                    res.attributes.get(attr_name),
                    base.attributes.get(attr_name),
                    severity,
                )
                if f is not None:
                    findings.append(f)

            # Attributes inside nested blocks (root_block_device, …).
            for block_type, force_new_attrs in spec.nested_blocks.items():
                head_blk = _find_block(res.blocks, block_type)
                base_blk = _find_block(base.blocks, block_type)
                if head_blk is None or base_blk is None:
                    continue  # block absent in one revision; not a value change
                for attr_name in force_new_attrs:
                    f = _compare_attr(
                        in_.path,
                        res.address(),
                        res.type,
                        attr_name,
                        block_type,
                        head_blk.attributes.get(attr_name),
                        base_blk.attributes.get(attr_name),
                        severity,
                    )
                    if f is not None:
                        findings.append(f)

        return findings


def _compare_attr(
    path: str,
    resource: str,
    res_type: str,
    attr_name: str,
    block_context: str,
    head: Attribute | None,
    base: Attribute | None,
    severity: Severity,
) -> Finding | None:
    if head is None or base is None:
        return None

    location = f"{block_context}.{attr_name}" if block_context else attr_name

    # When both revisions have the attribute but one or both values reference a
    # variable/expression we can't resolve statically, emit a lower-severity
    # informational finding instead of silently skipping — the user should
    # verify the value won't change at plan time.
    if not head.is_literal or not base.is_literal:
        return Finding(
            file=path,
            line=head.range.start.line,
            category=Category.FORCE_NEW_CHANGE,
            rule_name="force_new_change",
            severity=Severity.LOW,
            resource=resource,
            message=(
                f'"{location}" is a ForceNew attribute on {res_type} and uses a non-literal '
                "expression — verify the resolved value won't change at plan time "
                "(would trigger destroy+recreate)"
            ),
        )
    if head.raw_value == base.raw_value:
        return None

    return Finding(
        file=path,
        line=head.range.start.line,
        category=Category.FORCE_NEW_CHANGE,
        rule_name="force_new_change",
        severity=severity,
        resource=resource,
        message=(
            f'"{location}" changed from "{base.raw_value}" to "{head.raw_value}" — this '
            f"attribute is ForceNew on {res_type} and will destroy + recreate the resource "
            "on apply"
        ),
    )


def _find_block(blocks: list[NestedBlock], block_type: str) -> NestedBlock | None:
    for b in blocks:
        if b.type == block_type:
            return b
    return None


# --- missing prevent_destroy ---------------------------------------------


class MissingLifecycleRule:
    """Signale les ressources critiques à état — bases de données, volumes, … —
    qui ne déclarent pas lifecycle { prevent_destroy = true }, et restent donc
    exposées à une suppression accidentelle par un apply négligent."""

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        if kb is None:
            return []
        findings: list[Finding] = []

        for res in in_.head_resources:
            # prevent_destroy guards a managed resource. Modules and data
            # sources have nothing for it to protect.
            if res.kind is not Kind.RESOURCE:
                continue
            if not kb.is_critical(res.type):
                continue
            if res.prevent_destroy_value is True:
                continue  # properly protected

            line = res.def_range.start.line
            fix: Fix | None = None

            if res.has_lifecycle_block and res.prevent_destroy_value is False:
                # lifecycle block exists but prevent_destroy is explicitly false
                line = res.prevent_destroy_range.start.line
                detail = (
                    f"{res.type} explicitly sets prevent_destroy = false — remove this or "
                    "set it to true to protect against accidental deletion"
                )
                suggestion = "  prevent_destroy = true"
                # Flipping one literal in place: the narrowest fix there is.
                fix = _as_fix(
                    replace_attr_line(
                        in_.head_source,
                        res.prevent_destroy_range,
                        "prevent_destroy",
                        "prevent_destroy = true",
                    )
                )
            elif res.has_lifecycle_block and res.prevent_destroy_value is None:
                # lifecycle block exists but prevent_destroy is absent from it
                detail = (
                    f"{res.type} has a lifecycle block but is missing prevent_destroy = true "
                    "— add it to guard against accidental deletion"
                )
                suggestion = "  prevent_destroy = true"
                fix = _as_fix(
                    insert_into_block(
                        in_.head_source, res.lifecycle_range, "prevent_destroy = true"
                    )
                )
            else:
                # no lifecycle block at all
                detail = (
                    f"{res.type} is a stateful/critical resource with no "
                    "lifecycle { prevent_destroy = true } guard"
                )
                suggestion = "lifecycle {\n  prevent_destroy = true\n}"
                # The block goes just inside the resource header. Anywhere in
                # the body would be equally valid HCL, but the header is the
                # one line guaranteed to exist and to be unambiguous.
                fix = _as_fix(
                    insert_into_block(
                        in_.head_source,
                        res.def_range,
                        "lifecycle {",
                        "  prevent_destroy = true",
                        "}",
                    )
                )

            findings.append(
                Finding(
                    file=in_.path,
                    line=line,
                    category=Category.MISSING_LIFECYCLE,
                    rule_name="missing_lifecycle",
                    severity=Severity.MEDIUM,
                    resource=res.address(),
                    cloud_name=cloudname.of(res),
                    message=detail,
                    suggestion=suggestion,
                    fix=fix,
                )
            )

        return findings


# --- unpinned versions ----------------------------------------------------

#: The Terraform Registry's NAMESPACE/NAME/PROVIDER (optionally prefixed with a
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

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        findings: list[Finding] = []
        for res in in_.head_resources:
            if res.kind is not Kind.MODULE:
                continue
            findings.extend(_check_module_source(in_.path, res))
        findings.extend(_check_required_providers(in_.path, in_.head_source))
        return findings


def _check_module_source(path: str, res: Resource) -> list[Finding]:
    source = res.attributes.get("source")
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
                resource=res.address(),
                cloud_name=cloudname.of(res),
                message=message,
                suggestion=suggestion,
            )
        ]

    # A local path is versioned by this repository's own history; there is
    # nothing to pin.
    if value.startswith(("./", "../")):
        return []

    if _is_git_source(value):
        m = _GIT_REF_PARAM.search(value)
        if m is None:
            return finding(
                f'module source "{value}" has no ?ref= — every apply takes whatever the '
                "default branch says at that moment, so the plan reviewed here is not the "
                "plan that runs",
                f'source = "{value}?ref=v1.2.3"  # a tag or a commit SHA',
            )
        ref = m.group(1)
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
        v = res.attributes.get("version")
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


def _check_required_providers(path: str, source: bytes) -> list[Finding]:
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
    for m in _REQUIRED_PROVIDER_ENTRY.finditer(body):
        name = m.group(1)
        entry = m.group(2)
        if "version" in entry:
            continue
        findings.append(
            Finding(
                file=path,
                line=start_line + body[: m.start()].count("\n"),
                category=Category.UNPINNED_VERSION,
                rule_name="unpinned_version",
                severity=Severity.MEDIUM,
                resource="provider." + name,
                message=(
                    f'provider "{name}" declares no version constraint — a new major '
                    "release of it can change or break this configuration with no commit "
                    "here to explain why"
                ),
                suggestion=(
                    f'{name} = {{\n  source  = "hashicorp/{name}"\n  version = "~> 5.0"\n}}'
                ),
            )
        )
    return findings


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


# --- IAM wildcards --------------------------------------------------------

#: The attributes whose value is an IAM policy document.
#:
#: Matched by exact name rather than by suffix. "policy" as a substring appears
#: on plenty of attributes that hold a policy *name* or ARN — policy_arn,
#: iam_policy_name, ssl_policy — and reading one of those as a document would
#: produce a finding about text that is not a policy at all.
_POLICY_ATTR_NAMES = frozenset(
    {
        "policy",
        "assume_role_policy",
        "policy_document",
        "access_policy",
        "repository_policy",
        "bucket_policy",
    }
)

#: Action = "*" / "Action": "*" / Action = ["*"], in HCL object syntax or JSON.
#: NotAction is deliberately absent: it is rare, and its wildcard semantics are
#: inverted.
_WILDCARD_ACTION_RE = re.compile(r'"?\bAction"?\s*[:=]\s*(?:\[\s*)?"\*"', re.IGNORECASE)

#: Resource = "*", used only to decide whether a wildcard action is an
#: account-wide grant or merely a broad one.
_WILDCARD_RESOURCE_RE = re.compile(r'"?\bResource"?\s*[:=]\s*(?:\[\s*)?"\*"', re.IGNORECASE)

#: Principal = "*" and Principal = { AWS = "*" }, the two spellings of
#: "anyone". The optional middle group absorbs the AWS/Service wrapper without
#: allowing a nested brace, so it cannot run past the end of the principal
#: block and match an unrelated star further down.
_WILDCARD_PRINCIPAL_RE = re.compile(
    r'"?\bPrincipal"?\s*[:=]\s*(?:\{[^{}]*?"?AWS"?\s*[:=]\s*)?(?:\[\s*)?"\*"', re.IGNORECASE
)

#: Any Condition key at all. Its presence suppresses the principal check.
_CONDITION_RE = re.compile(r'"?\bCondition"?\s*[:=]', re.IGNORECASE)


class IAMWildcardRule:
    """Signale les documents de politique IAM qui accordent toutes les actions,
    ou qui accordent à tous les principaux.

    # Pourquoi ceci est compilé plutôt que déclaratif

    Le matcher ne voit que les valeurs d'attributs qui s'évaluent statiquement
    en littéral, et une politique IAM moderne ne le fait presque jamais. La
    forme qu'emploie la documentation du fournisseur AWS, et que reproduit le
    Terraform généré, est

        policy = jsonencode({ Statement = [{ Action = "*", Resource = "*" }] })

    soit un appel de fonction sur une expression d'objet. Le parseur ne la
    résout à rien, donc `value_matches` n'a rien à comparer. Les politiques en
    heredoc, elles, arrivent bien en littéraux et pourraient être comparées —
    mais écrire la règle pour la seule forme qui se trouve être visible
    reviendrait à ce que le scanner attrape l'écriture ancienne et rare, et rate
    celle que les gens écrivent réellement.

    Cette règle travaille donc sur la plage de source brute de l'attribut, que
    le parseur enregistre même quand il ne peut pas évaluer l'expression.

    # Ce qu'elle ne signale délibérément pas

    `Resource: "*"` tout seul. C'est incontournable pour toute une famille
    d'actions dont l'API ne prend aucun ARN de ressource —
    s3:ListAllMyBuckets, ec2:DescribeInstances, la plupart des iam:List* —
    donc une règle qui le signalerait se déclencherait sur une large part des
    politiques correctes. Une ressource joker n'est rapportée ici que couplée à
    une action joker, où la paire signifie « administrateur ».

    Un `Principal: "*"` dans un document qui porte aussi une Condition. Le motif
    à l'échelle d'une organisation — principal public restreint par
    aws:PrincipalOrgID ou aws:SourceArn — est à la fois courant et correct, et
    distinguer les deux demanderait un cloisonnement par déclaration que cette
    règle ne tente pas. Étouffer tout le document dès qu'une Condition apparaît
    échange un faux négatif contre un faux positif, ce qui est le bon sens de
    l'échange : c'est une accusation infondée qui fait désactiver un scanner.
    """

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        if not in_.head_source:
            # Without the raw source there is nothing to read: this rule's
            # whole input is the text the parser could not evaluate. Unit tests
            # that build a FileInput by hand simply get no findings, which is
            # the same contract the fix-emitting rules already have.
            return []

        findings: list[Finding] = []
        for res in in_.head_resources:
            # Sorted, not raw dict order: findings are compared against a golden
            # file, and source order would make that file rewrite itself when
            # someone reorders two attributes.
            for name in sorted(res.attributes):
                if name not in _POLICY_ATTR_NAMES:
                    continue
                attribute = res.attributes[name]
                body = attribute.range.slice(in_.head_source).decode("utf-8", errors="replace")
                if not body:
                    continue
                findings.extend(_check_policy_body(in_.path, res, attribute, body))
        return findings


def _check_policy_body(path: str, res: Resource, attribute: Attribute, body: str) -> list[Finding]:
    findings: list[Finding] = []

    m = _WILDCARD_ACTION_RE.search(body)
    if m is not None:
        if _WILDCARD_RESOURCE_RE.search(body):
            detail = (
                f'the IAM policy on {res.address()} grants Action "*" on Resource "*" — '
                "this is unrestricted administrator access to the account, which is almost "
                "never what a service needs"
            )
        else:
            detail = (
                f'the IAM policy on {res.address()} grants Action "*" — every action in '
                "every AWS service, including the IAM calls that would let a holder grant "
                "itself anything else"
            )
        findings.append(
            Finding(
                file=path,
                line=_line_of_offset(body, m.start(), attribute.range.start.line),
                category=Category.PERMISSIVE_IAM,
                rule_name="iam_wildcard",
                severity=Severity.HIGH,
                resource=res.address(),
                cloud_name=cloudname.of(res),
                message=detail,
                suggestion=(
                    "# Name the actions this actually needs, and the resources it needs "
                    "them on:\n"
                    'Action   = ["s3:GetObject", "s3:PutObject"]\n'
                    'Resource = ["${aws_s3_bucket.data.arn}/*"]'
                ),
            )
        )

    # A public principal narrowed by a Condition is the org-wide pattern and is
    # correct; see the class docstring for why this suppression is
    # document-wide rather than per-statement.
    if not _CONDITION_RE.search(body):
        pm = _WILDCARD_PRINCIPAL_RE.search(body)
        if pm is not None:
            findings.append(
                Finding(
                    file=path,
                    line=_line_of_offset(body, pm.start(), attribute.range.start.line),
                    category=Category.PERMISSIVE_IAM,
                    rule_name="iam_wildcard",
                    severity=Severity.HIGH,
                    resource=res.address(),
                    cloud_name=cloudname.of(res),
                    message=(
                        f'the policy on {res.address()} names Principal "*" with no '
                        "Condition — this grants the listed actions to every AWS account "
                        "on earth, not to every principal in yours"
                    ),
                    suggestion=(
                        '# Name the accounts or roles, or keep "*" and narrow it:\n'
                        "Condition = {\n"
                        '  StringEquals = { "aws:PrincipalOrgID" = "o-example" }\n'
                        "}"
                    ),
                )
            )

    return findings


def _line_of_offset(body: str, offset: int, start_line: int) -> int:
    """Convertit un décalage dans le texte d'un attribut en ligne de fichier,
    pour qu'un joker enfoui dans un bloc jsonencode de quarante lignes soit
    rapporté là où il est écrit plutôt qu'en tête de l'attribut."""
    if offset < 0 or offset > len(body):
        return start_line
    return start_line + body[:offset].count("\n")


# --- static cost estimate -------------------------------------------------


class StaticCostRule:
    """Estime le coût mensuel des ressources directement depuis le diff .tf, en
    utilisant la même tarification par type que la règle de coût fondée sur le
    plan — pour la majorité des dépôts qui ne branchent jamais de JSON de plan
    sur le scan.

    En fournir un est strictement meilleur (cela voit les count, for_each et
    valeurs calculées), ce qui est pourquoi le CLI n'exécute cette règle que
    lorsqu'aucun plan n'est donné : une même PR ne doit pas être facturée deux
    fois par deux estimateurs qui pourraient être en désaccord.

    Ce qu'une estimation à partir de la seule source peut honnêtement affirmer,
    et rien de plus :

      - Une ressource NOUVELLE d'un type tarifé coûte environ son prix
        catalogue. Rapportée quand cela franchit le seuil.
      - Un attribut moteur de prix MODIFIÉ (instance_type et consorts) déplace
        l'estimation de A vers B. Rapporté quand la hausse franchit le seuil —
        les baisses ne sont jamais des découvertes, dépenser moins n'a pas
        besoin d'une barrière.

    Les multiplicateurs count et for_each sont délibérément ignorés plutôt que
    devinés : sous-estimer le coût d'une flotte est mauvais, mais inventer un
    nombre est pire.
    """

    __slots__ = ("threshold_usd",)

    def __init__(self, threshold_usd: float) -> None:
        #: The estimated monthly increase that triggers a finding. Zero
        #: disables the rule (it shouldn't be constructed at all then; the
        #: guard is defence in depth).
        self.threshold_usd = threshold_usd

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        if self.threshold_usd <= 0 or kb is None:
            return []

        findings: list[Finding] = []
        for res in in_.head_resources:
            if res.kind is not Kind.RESOURCE:
                continue
            spec = kb.pricing_for(res.type)
            if spec is None:
                continue

            attr_value = _pricing_attr_value(res, spec)
            new_cost = spec.monthly_cost(attr_value)

            base = in_.base_resources.get(res.address())
            if base is None:
                if new_cost >= self.threshold_usd:
                    findings.append(
                        Finding(
                            file=in_.path,
                            line=res.def_range.start.line,
                            category=Category.COST_IMPACT,
                            rule_name="static_cost",
                            severity=Severity.MEDIUM,
                            resource=res.address(),
                            cloud_name=cloudname.of(res),
                            message=(
                                f"new {res.type} adds an estimated ${new_cost:.0f}/month"
                                f"{_describe_pricing_driver(spec, attr_value)} — static "
                                "list-price estimate, not a quote; count/for_each not included"
                            ),
                        )
                    )
                continue

            old_cost = spec.monthly_cost(_pricing_attr_value(base, spec))
            if new_cost - old_cost >= self.threshold_usd:
                findings.append(
                    Finding(
                        file=in_.path,
                        line=_pricing_attr_line(res, spec),
                        category=Category.COST_IMPACT,
                        rule_name="static_cost",
                        severity=Severity.MEDIUM,
                        resource=res.address(),
                        cloud_name=cloudname.of(res),
                        message=(
                            f"{res.type} estimated cost rises from ${old_cost:.0f} to "
                            f"${new_cost:.0f}/month"
                            f"{_describe_pricing_driver(spec, attr_value)} — static "
                            "list-price estimate, not a quote"
                        ),
                    )
                )
        return findings


def _pricing_attr_value(res: Resource, spec: PricingSpec) -> str:
    """La valeur littérale de l'attribut moteur de prix, « » quand il n'y en a
    pas ou qu'elle n'est pas connue statiquement — `monthly_cost` retombe alors
    sur le chiffre par défaut du type, ce qui est la réponse honnête pour une
    taille que le scanner ne peut pas voir."""
    if not spec.attribute:
        return ""
    attribute = res.attributes.get(spec.attribute)
    if attribute is not None and attribute.is_literal:
        return attribute.raw_value
    return ""


def _pricing_attr_line(res: Resource, spec: PricingSpec) -> int:
    """Ancre une découverte de changement de coût sur l'attribut qui a changé le
    nombre, avec repli sur l'en-tête de la ressource."""
    if spec.attribute:
        attribute = res.attributes.get(spec.attribute)
        if attribute is not None:
            return attribute.range.start.line
    return res.def_range.start.line


def _describe_pricing_driver(spec: PricingSpec, attr_value: str) -> str:
    if not spec.attribute or not attr_value:
        return ""
    return f' ({spec.attribute} = "{attr_value}")'
