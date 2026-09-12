"""Évaluation des définitions déclaratives de règles.

Port de internal/rules/declarative.go.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import cloudname
from ..parser import Attribute, NestedBlock, Resource
from ..report.finding import Category, Finding, Fix, Severity
from ..ruledef import Match, Rule
from ..schema import KnowledgeBase
from .base import FileInput
from .entropy import byte_len, is_public_by_shape
from .fix import credential_var_name, replace_attr_line, via_suffix
from .predicates import CONFIRM_PREDICATES, VALUE_PREDICATES
from .template import expand, expand_all, go_quote


@dataclass(slots=True, frozen=True)
class AttrLocation:
    """Un endroit où une valeur peut se trouver : un attribut propre à une
    ressource, ou un attribut à l'intérieur d'un de ses blocs imbriqués."""

    name: str
    attribute: Attribute
    #: None for a top-level attribute.
    block: NestedBlock | None = None


class DeclarativeRule:
    """Évalue une ou plusieurs définitions de règles qui examinent le même genre d'emplacement."""

    __slots__ = ("scope", "specs")

    def __init__(self, specs: list[Rule], scope: str) -> None:
        self.specs = specs
        self.scope = scope

    def check(self, file_input: FileInput, knowledge_base: KnowledgeBase | None) -> list[Finding]:
        findings: list[Finding] = []
        for resource in file_input.head_resources:
            if self.scope == "resource_name":
                finding = self._check_resource_name(file_input, resource)
                if finding is not None:
                    findings.append(finding)
                continue
            for location in self._locations(resource):
                finding = self._check_location(file_input, resource, location)
                if finding is not None:
                    findings.append(finding)
        return findings

    def _locations(self, resource: Resource) -> list[AttrLocation]:
        """Les attributs candidats pour la portée de cette règle."""
        matcher = self.specs[0].match
        assert matcher is not None  # guaranteed: a declarative rule always has one
        locations: list[AttrLocation] = []

        if matcher.scope in ("attribute", "any_attribute"):
            locations.extend(
                AttrLocation(name=name, attribute=resource.attributes[name])
                for name in sorted(resource.attributes)
            )
        if matcher.scope in ("block_attribute", "any_attribute"):
            for block in resource.blocks:
                if matcher.block_types and block.type not in matcher.block_types:
                    continue
                locations.extend(
                    AttrLocation(name=name, attribute=block.attributes[name], block=block)
                    for name in sorted(block.attributes)
                )
        return locations

    def _check_location(
        self, file_input: FileInput, resource: Resource, location: AttrLocation
    ) -> Finding | None:
        """Exécute les alternatives du groupe contre un attribut et rend la
        première découverte produite."""
        for spec in self.specs:
            matcher = spec.match
            if matcher is None or not matches_resource(matcher, resource):
                continue
            bits, ok = matches_attr(matcher, location.name, location.attribute)
            if not ok:
                continue
            return self._finding(file_input, spec, resource, location, bits)
        return None

    def _check_resource_name(self, file_input: FileInput, resource: Resource) -> Finding | None:
        for spec in self.specs:
            matcher = spec.match
            if matcher is None or not matches_resource(matcher, resource):
                continue
            if matcher.name_re is None or not matcher.name_re.search(resource.name):
                continue
            return Finding(
                file=file_input.path,
                line=resource.def_range.start.line,
                category=Category(spec.category),
                rule_name=spec.id,
                cloud_name=cloudname.of(resource),
                severity=Severity(spec.severity),
                resource=resource.address(),
                message=expand(spec.message, base_vars(resource)),
            )
        return None

    def _finding(
        self,
        file_input: FileInput,
        spec: Rule,
        resource: Resource,
        location: AttrLocation,
        bits: float,
    ) -> Finding:
        variables = base_vars(resource)
        variables["attr"] = location.name
        variables["attr_q"] = go_quote(location.name)
        variables["value"] = location.attribute.raw_value
        variables["value_q"] = go_quote(location.attribute.raw_value)
        variables["length"] = str(byte_len(location.attribute.raw_value))
        variables["label"] = spec.label
        variables["via"] = via_suffix(location.attribute)
        variables["bits"] = f"{bits:.1f}"

        block_type = ""
        if location.block is not None:
            block_type = location.block.type
            variables["block"] = block_type
            variables["location"] = f"(inside {block_type} block) "
        else:
            variables["location"] = ""
        variables["var"] = credential_var_name(resource, block_type, location.name)

        return Finding(
            file=file_input.path,
            line=location.attribute.range.start.line,
            category=Category(spec.category),
            rule_name=spec.id,
            cloud_name=cloudname.of(resource),
            severity=Severity(spec.severity),
            resource=resource.address(),
            message=expand(spec.message, variables),
            suggestion=expand(spec.suggestion, variables),
            fix=build_fix(spec, file_input.head_source, location, variables),
        )


def build_fix(
    spec: Rule, source: bytes, loc: AttrLocation, variables: dict[str, str]
) -> Fix | None:
    """Rend un correctif déclaratif, ou None quand il ne peut pas être produit exactement."""
    if spec.fix is None:
        return None
    # The literal was reached through a variable or a local, so the line under
    # this finding already reads `password = var.db_password` and is correct.
    # Rewriting it to point at a different variable would fix nothing while
    # looking like it had — the value lives in the declaration elsewhere.
    if spec.fix.skip_when_resolved and loc.attribute.resolved_from:
        return None

    lines = expand_all(spec.fix.lines, variables)
    edit = replace_attr_line(source, loc.attribute.range, loc.name, lines[0])
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


def matches_attr(m: Match, name: str, attribute: Attribute) -> tuple[float, bool]:
    """Applique chaque condition au niveau de la valeur, en rendant la mesure
    produite par le prédicat pour que le message puisse la citer."""
    if m.literal is not None and m.literal != attribute.is_literal:
        return 0.0, False
    if m.min_length > 0 and byte_len(attribute.raw_value) < m.min_length:
        return 0.0, False

    if m.attr_names and name not in m.attr_names:
        return 0.0, False
    if m.attr_name_re is not None and not m.attr_name_re.search(name):
        return 0.0, False
    if m.attr_name_not_re is not None and m.attr_name_not_re.search(name):
        return 0.0, False
    if m.attr_name_contains and m.attr_name_contains.lower() not in name.lower():
        return 0.0, False

    # Avant les motifs, et non après : `value_matches` n'est pas ancré, donc il
    # trouve sa fenêtre à l'intérieur d'un ARN aussi bien que dans un secret, et
    # `confirm` ne regarde ensuite que la fenêtre. La valeur entière est la
    # seule chose qui puisse dire « ceci est public ».
    if m.value_not_public and is_public_by_shape(attribute.raw_value):
        return 0.0, False
    if m.value_not_one_of and attribute.raw_value in m.value_not_one_of:
        return 0.0, False
    if m.value_contains and m.value_contains not in attribute.raw_value:
        return 0.0, False
    if m.value_re is not None:
        found = m.value_re.search(attribute.raw_value)
        if found is None or not found.group(0):
            return 0.0, False
        # The confirmation judges the substring the regex found, not the whole
        # value: a secret inside a longer string must still be caught, and a
        # long benign string must not be rescued by its benign parts.
        if m.confirm and not CONFIRM_PREDICATES[m.confirm](found.group(0)):
            return 0.0, False
    if m.predicate:
        bits, ok = VALUE_PREDICATES[m.predicate](attribute.raw_value)
        if not ok:
            return 0.0, False
        return bits, True

    return 0.0, True
