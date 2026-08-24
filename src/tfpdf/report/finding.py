"""Les découvertes produites par le moteur de règles.

Port de internal/report/finding.go.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    """Niveaux de sévérité, du plus faible au plus fort."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def at_least(self, other: Severity | str) -> bool:
        """Dit si ceci est au moins aussi sévère que `other`.

        `other` n'est délibérément pas restreint à une `Severity`. Un seuil
        configuré arrive en texte libre — `SCANNER_BLOCK_THRESHOLD`, une ligne
        `block_threshold:`, une politique d'organisation — et le `severityRank`
        de Go est un map, donc une valeur non reconnue y vaut le rang 0 et
        chaque découverte se compare comme l'atteignant ou la dépassant. C'est
        un vrai piège — une faute de frappe transforme le scanner en « bloque
        sur tout » — mais c'est le comportement livré, et lever une exception
        ici transformerait la même faute en trace d'appel. Le CLI le dit sur
        stderr plutôt que de diverger ; voir `cli.config.warn_unknown_threshold`.
        """
        return _SEVERITY_RANK[self] >= _SEVERITY_RANK.get(other, 0)  # type: ignore[arg-type]


_SEVERITY_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class Category(StrEnum):
    """Identifie quelle règle de détection a produit une découverte."""

    UNKNOWN_ATTRIBUTE = "unknown_attribute"
    UNPINNED_VERSION = "unpinned_version"
    TUTORIAL_PATTERN = "tutorial_pattern"
    FORCE_NEW_CHANGE = "force_new_change"
    MISSING_LIFECYCLE = "missing_lifecycle"

    # Guards that were explicitly switched off. Every rule behind these matches
    # a value someone wrote — never an absent attribute — because a missing
    # setting is the provider default on hundreds of resource types and
    # reporting those is how a scanner earns the mute button.
    #
    # They are four categories rather than one because suppression is
    # per-category: a team that has decided its buckets are public should be
    # able to say so without also silencing unencrypted volumes.
    PUBLIC_EXPOSURE = "public_exposure"
    ENCRYPTION_DISABLED = "encryption_disabled"
    PERMISSIVE_IAM = "permissive_iam"
    AUDIT_DISABLED = "audit_disabled"

    # Phase 2 categories: require a `terraform show -json` plan supplied via
    # --plan-json. Unlike the categories above, these are derived from
    # Terraform's own diff engine, not a heuristic over the .tf source.
    CONFIRMED_REPLACE = "confirmed_replace"
    UNEXPECTED_DRIFT = "unexpected_drift"
    LARGE_BLAST_RADIUS = "large_blast_radius"
    COST_IMPACT = "cost_impact"


@dataclass(slots=True)
class Fix:
    """Un remplacement exactement applicable pour les lignes
    [start_line, end_line].

    Délibérément plus étroit que `Finding.suggestion`. Une suggestion est
    proche de la prose : un extrait qu'un humain lit et adapte, libre de faire
    référence à une variable qui n'existe pas encore ou de montrer deux
    modifications à deux endroits. Un Fix est le texte littéral que ces lignes
    doivent devenir, parce que GitHub le rend en bloc `suggestion` dont le
    bouton « Commit suggestion » l'écrit dans la branche sans être lu. Tout ce
    qui ne serait pas exact à l'octet près commettrait du HCL cassé au nom de
    quelqu'un d'autre.

    Une règle ne pose donc un Fix que lorsqu'elle peut nommer le remplacement
    avec certitude : la valeur est écrite en ligne (et non atteinte via une
    variable qu'elle ne peut pas réécrire), elle occupe des lignes entières, et
    le correctif générique est sans ambiguïté. Toute autre découverte reçoit
    quand même sa suggestion dans le commentaire de synthèse. Un Fix absent est
    le cas normal, pas une lacune.
    """

    #: Inclusive, 1-based, referring to the file as it exists at the PR head.
    start_line: int
    end_line: int

    #: The replacement content, one entry per line, already indented to match
    #: the code it replaces. An empty list deletes the range.
    lines: list[str] = field(default_factory=list)

    #: Optional context rendered beneath the suggestion — used when applying
    #: the fix is correct but not sufficient on its own, e.g. swapping a
    #: hardcoded password for `var.x` also requires declaring `variable "x"`
    #: elsewhere in the module. Terraform fails loudly on the undeclared
    #: variable, so the half-applied state is safe; saying so up front is what
    #: stops it being a surprise.
    note: str = ""

    def text(self) -> str:
        """Les lignes de remplacement telles qu'elles apparaîtraient dans le
        fichier."""
        return "\n".join(self.lines)


@dataclass(slots=True)
class Finding:
    """Un risque unique détecté dans un diff Terraform."""

    file: str
    line: int
    #: One of the built-in categories, or a bare `"custom:<id>"` string from a
    #: custom rule. Go's `report.Category` is an open string type, so a custom
    #: rule can name anything; the enum here documents the built-in set without
    #: closing the field to it. Everything downstream treats a category as text
    #: — suppression matches on it, the renderers print it — so the two forms
    #: are interchangeable at every use site.
    category: Category | str
    severity: Severity
    #: "type.name" address, for context.
    resource: str
    message: str

    #: Which rule produced this finding — the `id` of its entry in the rule
    #: pack, `"custom:<id>"` for a custom rule.
    #:
    #: `category` does not answer this question. It is one-to-many by design:
    #: suppression is per-category, so several rules that a team would want to
    #: silence together deliberately share one. An `aws_s3_bucket` with
    #: `force_destroy = true` and no `prevent_destroy` carries two findings
    #: that agree on category *and* resource and come from different rules.
    #:
    #: It is not serialised anywhere. SARIF keeps using the category as its
    #: ruleId, the baseline file still matches on category+resource+file, and
    #: the PR comment does not print it — those are all output formats pinned
    #: byte-for-byte against the Go scanner, and this field exists for code
    #: that has to tell two findings apart, not for the report.
    #:
    #: Empty is allowed and means "nothing asked": a finding built by hand in a
    #: test, or one that no pack entry describes. Code that branches on it must
    #: therefore compare against a name, never assume it is non-empty.
    rule_name: str = ""

    #: Le nom que cette ressource porte réellement chez le fournisseur —
    #: `"prod-backups"`, là où `resource` porte `"aws_s3_bucket.backups"`.
    #:
    #: Les deux existent parce qu'ils répondent à deux questions. `resource`
    #: situe la découverte pour la personne qui relit la PR : c'est l'adresse
    #: qu'elle verra dans un plan. `cloud_name` est ce qu'il faut donner à une
    #: API pour parler de l'objet, et aucune API ne connaît l'adresse
    #: Terraform.
    #:
    #: Vide dès qu'on ne peut pas l'affirmer : type dont on ne sait pas quel
    #: attribut le nomme, attribut absent, ou nom construit à l'exécution. Un
    #: appelant doit traiter le vide comme « je ne sais pas » et ne rien
    #: conclure — surtout pas interroger le cloud avec, parce que le « cet
    #: objet n'existe pas » qui reviendrait est indiscernable d'une vraie
    #: absence. Voir `tfpdf.cloudname`.
    cloud_name: str = ""

    #: An optional, mechanically-generated HCL snippet showing how to fix the
    #: finding — not a computed byte-range patch against the real file (this
    #: tool never has write access to the repo), just a snippet the author can
    #: paste in. Populated only for categories where a safe, generic fix
    #: exists; empty otherwise.
    suggestion: str = ""

    #: When set, links to the provider documentation for the resource type this
    #: finding is about, pinned to the provider version the rule pack
    #: describes.
    #:
    #: It is what turns "attribute X is not a known argument of aws_instance"
    #: from an assertion into something checkable. A scanner that says an
    #: argument does not exist and offers no way to verify it gets argued with;
    #: one that links the argument list gets believed or corrected, and both
    #: outcomes are better.
    doc_url: str = ""

    #: The same fix expressed as an exact line replacement, which is what
    #: GitHub's one-click "Commit suggestion" button needs. See `Fix`.
    fix: Fix | None = None

    #: When true, excludes this finding from the blocking decision and from
    #: SARIF output — an admin accepted this specific finding (matched by
    #: category+resource+file, via the control plane's per-finding waivers,
    #: Starter+) with `waiver_note` as the justification. It still appears in
    #: the PR comment, in its own section, so a waived finding never just
    #: silently vanishes from the record.
    waived: bool = False
    waiver_note: str = ""
