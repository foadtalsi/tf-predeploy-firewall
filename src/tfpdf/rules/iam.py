"""Détection des permissions IAM trop larges dans les documents de politique."""

from __future__ import annotations

import re

from .. import cloudname
from ..parser import Attribute, Resource
from ..report.finding import Category, Finding, Severity
from ..schema import KnowledgeBase
from .base import FileInput

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

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        if not file_input.head_source:
            # Without the raw source there is nothing to read: this rule's
            # whole input is the text the parser could not evaluate. Unit tests
            # that build a FileInput by hand simply get no findings, which is
            # the same contract the fix-emitting rules already have.
            return []

        findings: list[Finding] = []
        for resource in file_input.head_resources:
            # Sorted, not raw dict order: findings are compared against a golden
            # file, and source order would make that file rewrite itself when
            # someone reorders two attributes.
            for name in sorted(resource.attributes):
                if name not in _POLICY_ATTR_NAMES:
                    continue
                attribute = resource.attributes[name]
                body = attribute.range.slice(file_input.head_source).decode(
                    "utf-8", errors="replace"
                )
                if not body:
                    continue
                findings.extend(_check_policy_body(file_input.path, resource, attribute, body))
        return findings


def _check_policy_body(
    path: str, resource: Resource, attribute: Attribute, body: str
) -> list[Finding]:
    findings: list[Finding] = []

    match = _WILDCARD_ACTION_RE.search(body)
    if match is not None:
        if _WILDCARD_RESOURCE_RE.search(body):
            detail = (
                f'the IAM policy on {resource.address()} grants Action "*" on Resource "*" — '
                "this is unrestricted administrator access to the account, which is almost "
                "never what a service needs"
            )
        else:
            detail = (
                f'the IAM policy on {resource.address()} grants Action "*" — every action in '
                "every AWS service, including the IAM calls that would let a holder grant "
                "itself anything else"
            )
        findings.append(
            Finding(
                file=path,
                line=_line_of_offset(body, match.start(), attribute.range.start.line),
                category=Category.PERMISSIVE_IAM,
                rule_name="iam_wildcard",
                severity=Severity.HIGH,
                resource=resource.address(),
                cloud_name=cloudname.of(resource),
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
                    resource=resource.address(),
                    cloud_name=cloudname.of(resource),
                    message=(
                        f'the policy on {resource.address()} names Principal "*" with no '
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
