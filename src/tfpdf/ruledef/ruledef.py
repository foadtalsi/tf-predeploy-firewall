"""Le format déclaratif des règles : ce qu'une règle cherche, comment la
découverte est formulée, quel prédicat la confirme, et sa documentation longue.

Port de internal/ruledef/ruledef.go.

N'importe rien du reste du scanner — ni parseur, ni types de rapport — pour que
le format reste indépendant du moteur qui l'évalue. Tout ce qui lit du YAML lit
un pack de règles.

**Aucun langage d'expression, aucun appel de code.** Une règle nomme un prédicat
pris dans un vocabulaire fixe fourni par le binaire. Le scanner tourne dans les
pipelines CI d'autres gens ; « les clients peuvent écrire du code qui s'exécute
ici » n'est pas un échange à faire.

**Expressions régulières :** tout passe par `re.search`, jamais `re.match`, pour
que les motifs non ancrés se comportent comme le `MatchString` de Go.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

#: The rule-pack format this binary understands. A pack declaring a newer
#: version is refused rather than partially interpreted: a rule whose semantics
#: the reader does not implement is a rule that silently matches nothing, which
#: looks exactly like a clean scan.
FORMAT_VERSION = 1

#: The only value `extends:` accepts today.
EXTENDS_BUILTIN = "builtin"

VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

VALID_SCOPES = frozenset({"attribute", "block_attribute", "any_attribute", "resource_name"})

#: Only the one action, because it is the only one a declarative rule can
#: currently reach: every declarative scope resolves to an attribute, and an
#: attribute has a line to overwrite but no block header to insert beneath.
#: Block insertion exists as a primitive (missing_lifecycle writes a whole
#: lifecycle block with it) and stays compiled until a scope that can address a
#: block header exists. Listing it here before then would let a pack ask for a
#: fix that silently never appears.
VALID_FIX_ACTIONS = frozenset({"replace_attr_line"})


class RulePackError(ValueError):
    """Un pack qui n'a pas pu être analysé ou validé.

    Bruyant par choix : un pack que le scanner ne lit qu'en partie est
    indiscernable d'un dépôt propre.
    """


@dataclass(slots=True)
class Fix:
    """Le remplacement en un clic proposé avec une découverte."""

    #: Names the compiled source-surgery primitive. The text has to reproduce
    #: the surrounding lines byte for byte, which is why this is a named
    #: operation rather than anything the YAML spells out itself.
    #:   replace_attr_line — swap the matched attribute's line
    #:   insert_into_block — add lines just inside a block header
    action: str = ""
    #: The replacement or inserted text, templated.
    lines: list[str] = field(default_factory=list)
    #: Shown with the suggestion, for the part applying it does not do. A fix
    #: that leaves the tree in a state the author did not expect has to say so.
    note: str = ""
    #: Withholds the fix when the value was reached through a variable or local
    #: rather than written inline. The line under the finding is then already
    #: correct and rewriting it would fix nothing while looking like it had.
    skip_when_resolved: bool = False


@dataclass(slots=True)
class Match:
    """La condition déclarative.

    Chaque champ posé doit être satisfait ; un Match vide ne correspond à rien,
    ce que la validation rejette plutôt que de signaler silencieusement chaque
    ressource du dépôt.
    """

    #: Selects what is walked:
    #:   attribute       — a resource's top-level attributes
    #:   block_attribute — attributes inside nested blocks
    #:   any_attribute   — both
    #:   resource_name   — the resource's local name (the second label)
    scope: str = ""

    #: Restricts to resource / data / module blocks. Empty means any.
    kinds: list[str] = field(default_factory=list)
    #: Exact provider type names; empty means any.
    resource_types: list[str] = field(default_factory=list)
    #: Restricts which nested blocks are walked; empty means all.
    block_types: list[str] = field(default_factory=list)

    attr_names: list[str] = field(default_factory=list)
    attr_name_matches: str = ""
    attr_name_not_matches: str = ""
    attr_name_contains: str = ""

    #: Requires the value to be statically known. A non-literal is an
    #: expression the scanner cannot evaluate, and guessing at one is how a
    #: rule earns a reputation for false positives.
    literal: bool | None = None
    min_length: int = 0

    value_matches: str = ""
    value_contains: str = ""
    value_not_one_of: list[str] = field(default_factory=list)

    #: Applies to scope: resource_name.
    name_matches: str = ""

    #: Names a predicate applied to the substring `value_matches` found, not to
    #: the whole value: the point is to judge the candidate the regex picked
    #: out. This is what separates a 40-character secret from a 40-character
    #: file path.
    confirm: str = ""

    #: Names a predicate applied to the whole value, for detectors that are a
    #: measurement rather than a shape.
    predicate: str = ""

    # Compiled once at load, so the evaluator never recompiles per file.
    attr_name_re: re.Pattern[str] | None = field(default=None, repr=False)
    attr_name_not_re: re.Pattern[str] | None = field(default=None, repr=False)
    value_re: re.Pattern[str] | None = field(default=None, repr=False)
    name_re: re.Pattern[str] | None = field(default=None, repr=False)

    def has_attr_condition(self) -> bool:
        return bool(
            self.attr_names
            or self.attr_name_matches
            or self.attr_name_not_matches
            or self.attr_name_contains
            or self.literal is not None
            or self.min_length > 0
            or self.value_matches
            or self.value_contains
            or self.value_not_one_of
            or self.predicate
        )

    def validate(self) -> None:
        if self.scope not in VALID_SCOPES:
            raise RulePackError(
                "match scope must be one of attribute/block_attribute/any_attribute/"
                f"resource_name, got {self.scope!r}"
            )
        if self.scope == "resource_name" and not self.name_matches:
            raise RulePackError("scope resource_name needs name_matches")
        if self.scope != "resource_name" and not self.has_attr_condition():
            raise RulePackError(
                "an attribute-scoped rule needs at least one condition — a match block "
                "with none would flag every attribute in the repository"
            )
        if self.confirm and not self.value_matches:
            raise RulePackError(
                "confirm applies to the text value_matches found, so value_matches is "
                "required with it"
            )

        self.attr_name_re = _compile_opt(self.attr_name_matches, "attr_name_matches")
        self.attr_name_not_re = _compile_opt(self.attr_name_not_matches, "attr_name_not_matches")
        self.value_re = _compile_opt(self.value_matches, "value_matches")
        self.name_re = _compile_opt(self.name_matches, "name_matches")


@dataclass(slots=True)
class Rule:
    """Un détecteur, ou les métadonnées d'un détecteur compilé."""

    id: str = ""
    category: str = ""
    severity: str = ""

    #: Names a compiled detector that owns this rule's traversal, for checks a
    #: declarative matcher cannot express: schema lookups, base versus head
    #: comparison, brace-matched source scanning. The rule still owns its
    #: severity, wording and documentation — only the walk is code.
    #:
    #: Empty means the rule is fully declarative and `match` drives it.
    engine: str = ""

    #: Ties ordered alternatives together. Within one group the first rule to
    #: match a given location wins and the rest are skipped, which is how a
    #: specific credential format takes precedence over the generic entropy
    #: fallback that would otherwise also fire on it.
    group: str = ""

    #: The human-readable name of what matched ("JWT token"), substituted into
    #: messages as {label} and returned by the exported value-matching helpers.
    label: str = ""

    match: Match | None = None

    message: str = ""
    suggestion: str = ""
    fix: Fix | None = None

    #: Engine-specific settings. Kept as strings so the format has one scalar
    #: type and no schema-per-engine.
    params: dict[str, str] = field(default_factory=dict)

    #: Switches one rule off. Only meaningful in a pack that extends another —
    #: it is how you turn off a single built-in detector without disowning the
    #: rest of its category, which is all `ignore_rules:` in the config can do.
    #: Disabling the whole of tutorial_pattern to silence one over-eager format
    #: would take the credential detection with it.
    disabled: bool = False

    def validate(self) -> None:
        if not self.id:
            raise RulePackError("id is required")
        # A disabling entry names a rule and nothing else — demanding a
        # category and a severity for something being switched off would mean
        # copying fields nobody reads, which then rot against the rule they
        # shadow. Merge drops these before the merged pack is validated.
        if self.disabled:
            return
        if not self.category:
            raise RulePackError("category is required")
        if self.severity not in VALID_SEVERITIES:
            raise RulePackError(
                f"severity must be one of low/medium/high/critical, got {self.severity!r}"
            )
        if not self.engine and self.match is None:
            raise RulePackError("a rule needs either an engine or a match block")
        if self.engine and self.match is not None:
            raise RulePackError(
                "engine and match are mutually exclusive — a compiled engine owns its own traversal"
            )
        if self.match is not None and not self.message:
            raise RulePackError("message is required")
        if self.match is not None:
            self.match.validate()
        if self.fix is not None:
            if self.match is None:
                raise RulePackError("fix is only meaningful on a declarative rule")
            if self.fix.action not in VALID_FIX_ACTIONS:
                raise RulePackError(
                    "fix action must be replace_attr_line or insert_into_block, got "
                    f"{self.fix.action!r}"
                )
            if not self.fix.lines:
                raise RulePackError("fix has no lines")


@dataclass(slots=True)
class CategoryDoc:
    """L'explication longue d'une catégorie, rendue sur une page d'alerte de
    scan de code et dans docs/rules.md — lue par quelqu'un qui n'a pas lancé le
    scan et n'en a aucun contexte.

    Une catégorie incapable de s'expliquer là est une catégorie qu'on désactive
    en bloc plutôt que de l'affiner.
    """

    category: str = ""
    title: str = ""
    full_description: str = ""
    markdown: str = ""


class Pack:
    """Un jeu complet de règles, tel que chargé depuis du YAML."""

    __slots__ = ("_by_cat", "_by_group", "_by_id", "_groups", "docs", "extends", "rules", "version")

    def __init__(
        self,
        version: int = 0,
        extends: str = "",
        rules: list[Rule] | None = None,
        docs: list[CategoryDoc] | None = None,
    ) -> None:
        self.version = version
        #: When set to "builtin", layers this pack on top of the one compiled
        #: into the scanner instead of replacing it: rules whose id already
        #: exists are overridden, new ids are added, everything else inherited.
        #:
        #: It exists because the two things people want are opposites. Adding
        #: an org's own rule must not silently drop the built-in ones.
        #: Correcting a built-in rule that misfires must be possible at all,
        #: which an add-only mechanism cannot do. Overriding by id is both, and
        #: it means a pack that changes one severity is four lines rather than
        #: a fork of the whole file.
        self.extends = extends
        self.rules: list[Rule] = rules or []
        #: Keyed by category rather than by rule because that is the
        #: granularity a reader meets it at: a code-scanning alert page shows
        #: one explanation per category, and the seven credential-format
        #: detectors all report as tutorial_pattern. Attaching prose per rule
        #: would mean seven copies of the same page, or an arbitrary rule
        #: owning it.
        self.docs: list[CategoryDoc] = docs or []

        self._by_id: dict[str, Rule] = {}
        self._by_group: dict[str, list[Rule]] = {}
        self._by_cat: dict[str, CategoryDoc] = {}
        self._groups: list[str] = []

    # --- lookups ----------------------------------------------------------

    def by_id(self, rule_id: str) -> Rule | None:
        return self._by_id.get(rule_id)

    def group(self, name: str) -> list[Rule]:
        """Les membres ordonnés d'un groupe nommé."""
        return self._by_group.get(name, [])

    def group_names(self) -> list[str]:
        """Chaque groupe, dans l'ordre de sa première apparition dans le pack."""
        return list(self._groups)

    def ungrouped(self) -> list[Rule]:
        """Les règles n'appartenant à aucun groupe, dans l'ordre du pack."""
        return [r for r in self.rules if not r.group]

    def categories(self) -> list[str]:
        """Chaque catégorie que le pack définit, dans l'ordre de première
        apparition."""
        out: list[str] = []
        seen: set[str] = set()
        for r in self.rules:
            if r.category not in seen:
                seen.add(r.category)
                out.append(r.category)
        return out

    def docs_for(self, category: str) -> CategoryDoc | None:
        return self._by_cat.get(category)

    def documented_categories(self) -> list[CategoryDoc]:
        """Les catégories portant de la documentation, dans l'ordre du pack —
        l'ordre dans lequel docs/rules.md est généré.
        """
        return list(self.docs)

    def require_ids(self, *ids: str) -> None:
        """Vérifie que chaque identifiant que le binaire va chercher par son nom
        est bien présent.

        Les aides exportées de détection d'identifiants lisent leurs motifs dans
        ce pack plutôt que d'en garder une seconde copie dans le code : un
        identifiant renommé désactiverait donc silencieusement la détection de
        secrets partout où ces aides servent — y compris dans les scanners
        .tfvars et terragrunt.
        """
        missing = [i for i in ids if i not in self._by_id]
        if missing:
            raise RulePackError(
                "rule pack is missing ids the scanner reads by name: " + ", ".join(missing)
            )

    # --- validation -------------------------------------------------------

    def index(self) -> None:
        """Valide chaque règle et construit les tables de recherche.

        Séparé de `load` pour qu'un pack fusionné soit vérifié exactement par le
        même code qu'un pack analysé : une fusion produisant quelque chose que
        `load` aurait rejeté est un bug qu'il vaut mieux attraper là où il se
        produit.
        """
        self._by_id = {}
        self._by_group = {}
        self._by_cat = {}
        self._groups = []

        for i, d in enumerate(self.docs):
            if not d.category:
                raise RulePackError(f"docs {i}: category is required")
            if d.category in self._by_cat:
                raise RulePackError(f"docs {i}: duplicate category {d.category!r}")
            self._by_cat[d.category] = d

        for i, r in enumerate(self.rules):
            try:
                r.validate()
            except RulePackError as exc:
                raise RulePackError(f"rule {i} ({r.id}): {exc}") from exc
            if r.id in self._by_id:
                raise RulePackError(f"rule {i}: duplicate id {r.id!r}")
            self._by_id[r.id] = r
            if r.group:
                if r.group not in self._by_group:
                    self._groups.append(r.group)
                self._by_group.setdefault(r.group, []).append(r)

        # Alternatives only take precedence over one another if they are
        # looking at the same thing. A group whose members walk different
        # scopes would have first-match-wins semantics that depend on which
        # rule happened to see a location first.
        for name, members in self._by_group.items():
            scope = ""
            for r in members:
                if r.match is None:
                    raise RulePackError(
                        f"rule {r.id!r}: a grouped rule must be declarative (group {name!r})"
                    )
                if not scope:
                    scope = r.match.scope
                    continue
                if r.match.scope != scope:
                    raise RulePackError(
                        f"group {name!r} mixes scopes ({scope} and {r.match.scope}) — "
                        "first-match-wins is only meaningful between rules that examine "
                        "the same location"
                    )


def _compile_opt(pattern: str, field_name: str) -> re.Pattern[str] | None:
    if not pattern:
        return None
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise RulePackError(f"{field_name}: {exc}") from exc


def _as_str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _match_from_dict(d: dict[str, Any]) -> Match:
    return Match(
        scope=str(d.get("scope", "")),
        kinds=_as_str_list(d.get("kinds")),
        resource_types=_as_str_list(d.get("resource_types")),
        block_types=_as_str_list(d.get("block_types")),
        attr_names=_as_str_list(d.get("attr_names")),
        attr_name_matches=str(d.get("attr_name_matches", "")),
        attr_name_not_matches=str(d.get("attr_name_not_matches", "")),
        attr_name_contains=str(d.get("attr_name_contains", "")),
        literal=d.get("literal"),
        min_length=int(d.get("min_length", 0) or 0),
        value_matches=str(d.get("value_matches", "")),
        value_contains=str(d.get("value_contains", "")),
        value_not_one_of=_as_str_list(d.get("value_not_one_of")),
        name_matches=str(d.get("name_matches", "")),
        confirm=str(d.get("confirm", "")),
        predicate=str(d.get("predicate", "")),
    )


def _fix_from_dict(d: dict[str, Any]) -> Fix:
    return Fix(
        action=str(d.get("action", "")),
        lines=_as_str_list(d.get("lines")),
        note=str(d.get("note", "")),
        skip_when_resolved=bool(d.get("skip_when_resolved", False)),
    )


def _rule_from_dict(d: dict[str, Any]) -> Rule:
    match_d = d.get("match")
    fix_d = d.get("fix")
    params = d.get("params") or {}
    return Rule(
        id=str(d.get("id", "")),
        category=str(d.get("category", "")),
        severity=str(d.get("severity", "")),
        engine=str(d.get("engine", "")),
        group=str(d.get("group", "")),
        label=str(d.get("label", "")),
        match=_match_from_dict(match_d) if isinstance(match_d, dict) else None,
        message=str(d.get("message", "")),
        suggestion=str(d.get("suggestion", "")),
        fix=_fix_from_dict(fix_d) if isinstance(fix_d, dict) else None,
        params={str(k): str(v) for k, v in params.items()},
        disabled=bool(d.get("disabled", False)),
    )


def load(data: bytes | str) -> Pack:
    """Analyse et valide entièrement un pack de règles.

    Chaque expression régulière est compilée et chaque énumération vérifiée au
    chargement, pour qu'une faute de frappe fasse échouer le scan bruyamment au
    lieu de produire une règle qui ne détecte rien en silence.
    """
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise RulePackError(f"parsing rule pack: {exc}") from exc

    if not isinstance(raw, dict):
        raise RulePackError("rule pack is not a mapping")

    version = int(raw.get("version", 0) or 0)
    if version == 0:
        raise RulePackError("rule pack has no version field")
    if version > FORMAT_VERSION:
        raise RulePackError(
            f"rule pack declares format version {version} but this binary understands "
            f"{FORMAT_VERSION} — upgrade the scanner rather than running it against a "
            "pack it can only partly read"
        )

    extends = str(raw.get("extends", "") or "")
    if extends and extends != EXTENDS_BUILTIN:
        raise RulePackError(f"extends must be {EXTENDS_BUILTIN!r} or omitted, got {extends!r}")

    rules_raw = raw.get("rules") or []
    if not rules_raw:
        raise RulePackError("rule pack declares no rules")

    docs_raw = raw.get("docs") or []
    pack = Pack(
        version=version,
        extends=extends,
        rules=[_rule_from_dict(r) for r in rules_raw],
        docs=[
            CategoryDoc(
                category=str(d.get("category", "")),
                title=str(d.get("title", "")),
                full_description=str(d.get("full_description", "")),
                markdown=str(d.get("markdown", "")),
            )
            for d in docs_raw
        ],
    )
    pack.index()
    return pack
