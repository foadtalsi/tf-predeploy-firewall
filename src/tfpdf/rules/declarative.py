"""Évaluation des définitions déclaratives de règles.

Port de internal/rules/declarative.go.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..parser import Attribute, NestedBlock, Resource
from ..report.finding import Category, Finding, Fix, Severity
from ..ruledef import Match, Rule
from ..schema import KnowledgeBase
from .base import FileInput
from .entropy import byte_len
from .fix import credential_var_name, replace_attr_line, via_suffix
from .predicates import CONFIRM_PREDICATES, VALUE_PREDICATES
from .template import expand, expand_all, go_quote


@dataclass(slots=True, frozen=True)
class AttrLocation:
    """Un endroit où une valeur peut se trouver : un attribut propre à une
    ressource, ou un attribut à l'intérieur d'un de ses blocs imbriqués."""

    name: str
    attr: Attribute
    #: None for a top-level attribute.
    block: NestedBlock | None = None


class DeclarativeRule:
    """Évalue une ou plusieurs définitions de règles qui examinent le même
    genre d'emplacement.

    Un groupe détient des alternatives ordonnées et la première qui correspond à
    un emplacement l'emporte. C'est ce qui fait qu'un JWT est rapporté comme un
    JWT plutôt que comme « une chaîne à forte entropie » : les formats
    spécifiques sont listés avant le repli statistique, et le repli n'a jamais
    la parole sur une valeur qui a déjà un nom. Une règle sans groupe est un
    groupe d'un seul élément, pour qu'il n'y ait qu'un seul chemin de code.
    """

    __slots__ = ("scope", "specs")

    def __init__(self, specs: list[Rule], scope: str) -> None:
        self.specs = specs
        self.scope = scope

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        findings: list[Finding] = []
        for res in in_.head_resources:
            if self.scope == "resource_name":
                f = self._check_resource_name(in_, res)
                if f is not None:
                    findings.append(f)
                continue
            for loc in self._locations(res):
                f = self._check_location(in_, res, loc)
                if f is not None:
                    findings.append(f)
        return findings

    def _locations(self, res: Resource) -> list[AttrLocation]:
        """Les attributs candidats pour la portée de cette règle.

        Triés par nom parce que l'ordre d'un dictionnaire suit l'insertion — qui
        suit l'ordre de la source — et qu'un scanner dont la sortie se décale
        quand quelqu'un permute deux attributs est un scanner dont personne ne
        peut comparer deux rapports. L'original Go trie pour la même raison,
        l'itération d'un map y étant randomisée.
        """
        m = self.specs[0].match
        assert m is not None  # guaranteed: a declarative rule always has one
        out: list[AttrLocation] = []

        if m.scope in ("attribute", "any_attribute"):
            out.extend(
                AttrLocation(name=name, attr=res.attributes[name])
                for name in sorted(res.attributes)
            )
        if m.scope in ("block_attribute", "any_attribute"):
            for blk in res.blocks:
                if m.block_types and blk.type not in m.block_types:
                    continue
                out.extend(
                    AttrLocation(name=name, attr=blk.attributes[name], block=blk)
                    for name in sorted(blk.attributes)
                )
        return out

    def _check_location(self, in_: FileInput, res: Resource, loc: AttrLocation) -> Finding | None:
        """Exécute les alternatives du groupe contre un attribut et rend la
        première découverte produite."""
        for spec in self.specs:
            m = spec.match
            if m is None or not matches_resource(m, res):
                continue
            bits, ok = matches_attr(m, loc.name, loc.attr)
            if not ok:
                continue
            return self._finding(in_, spec, res, loc, bits)
        return None

    def _check_resource_name(self, in_: FileInput, res: Resource) -> Finding | None:
        for spec in self.specs:
            m = spec.match
            if m is None or not matches_resource(m, res):
                continue
            if m.name_re is None or not m.name_re.search(res.name):
                continue
            return Finding(
                file=in_.path,
                line=res.def_range.start.line,
                category=Category(spec.category),
                severity=Severity(spec.severity),
                resource=res.address(),
                message=expand(spec.message, base_vars(res)),
            )
        return None

    def _finding(
        self, in_: FileInput, spec: Rule, res: Resource, loc: AttrLocation, bits: float
    ) -> Finding:
        variables = base_vars(res)
        variables["attr"] = loc.name
        variables["attr_q"] = go_quote(loc.name)
        variables["value"] = loc.attr.raw_value
        variables["value_q"] = go_quote(loc.attr.raw_value)
        variables["length"] = str(byte_len(loc.attr.raw_value))
        variables["label"] = spec.label
        variables["via"] = via_suffix(loc.attr)
        variables["bits"] = f"{bits:.1f}"

        block_type = ""
        if loc.block is not None:
            block_type = loc.block.type
            variables["block"] = block_type
            variables["location"] = f"(inside {block_type} block) "
        else:
            variables["location"] = ""
        variables["var"] = credential_var_name(res, block_type, loc.name)

        return Finding(
            file=in_.path,
            line=loc.attr.range.start.line,
            category=Category(spec.category),
            severity=Severity(spec.severity),
            resource=res.address(),
            message=expand(spec.message, variables),
            suggestion=expand(spec.suggestion, variables),
            fix=build_fix(spec, in_.head_source, loc, variables),
        )


def build_fix(spec: Rule, src: bytes, loc: AttrLocation, variables: dict[str, str]) -> Fix | None:
    """Rend un correctif déclaratif, ou None quand il ne peut pas être produit
    exactement.

    Tout chemin de sortie qui n'est pas un remplacement complet et à
    l'identique rend None : rater un correctif en un clic coûte un clic, en
    produire un faux commet du HCL cassé dans la branche de quelqu'un.
    """
    if spec.fix is None:
        return None
    # The literal was reached through a variable or a local, so the line under
    # this finding already reads `password = var.db_password` and is correct.
    # Rewriting it to point at a different variable would fix nothing while
    # looking like it had — the value lives in the declaration elsewhere.
    if spec.fix.skip_when_resolved and loc.attr.resolved_from:
        return None

    lines = expand_all(spec.fix.lines, variables)
    edit = replace_attr_line(src, loc.attr.range, loc.name, lines[0])
    if edit is None:
        return None
    return Fix(
        start_line=edit.start,
        end_line=edit.end,
        lines=edit.lines,
        note=expand(spec.fix.note, variables),
    )


def base_vars(res: Resource) -> dict[str, str]:
    return {
        "resource": res.address(),
        "type": res.type,
        "name": res.name,
        "name_q": go_quote(res.name),
    }


def matches_resource(m: Match, res: Resource) -> bool:
    """Applique les filtres au niveau du bloc. Des filtres vides correspondent à
    tout, pour qu'une règle n'énonce que ce qu'elle restreint réellement."""
    if m.kinds and str(res.kind) not in m.kinds:
        return False
    return not (m.resource_types and res.type not in m.resource_types)


def matches_attr(m: Match, name: str, attr: Attribute) -> tuple[float, bool]:
    """Applique chaque condition au niveau de la valeur, en rendant la mesure
    produite par le prédicat pour que le message puisse la citer."""
    if m.literal is not None and m.literal != attr.is_literal:
        return 0.0, False
    if m.min_length > 0 and byte_len(attr.raw_value) < m.min_length:
        return 0.0, False

    if m.attr_names and name not in m.attr_names:
        return 0.0, False
    if m.attr_name_re is not None and not m.attr_name_re.search(name):
        return 0.0, False
    if m.attr_name_not_re is not None and m.attr_name_not_re.search(name):
        return 0.0, False
    if m.attr_name_contains and m.attr_name_contains.lower() not in name.lower():
        return 0.0, False

    if m.value_not_one_of and attr.raw_value in m.value_not_one_of:
        return 0.0, False
    if m.value_contains and m.value_contains not in attr.raw_value:
        return 0.0, False
    if m.value_re is not None:
        found = m.value_re.search(attr.raw_value)
        if found is None or not found.group(0):
            return 0.0, False
        # The confirmation judges the substring the regex found, not the whole
        # value: a secret inside a longer string must still be caught, and a
        # long benign string must not be rescued by its benign parts.
        if m.confirm and not CONFIRM_PREDICATES[m.confirm](found.group(0)):
            return 0.0, False
    if m.predicate:
        bits, ok = VALUE_PREDICATES[m.predicate](attr.raw_value)
        if not ok:
            return 0.0, False
        return bits, True

    return 0.0, True
