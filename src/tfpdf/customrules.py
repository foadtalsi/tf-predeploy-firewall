"""Règles de détection définies par l'organisation, de façon déclarative.

Port de internal/customrules/customrules.go.

Du YAML : type de ressource, attribut ou bloc, et expression régulière — sans
que cet outil n'exécute jamais de code fourni par l'organisation. Un
interpréteur de DSL sans aucune surface `eval` ou `exec` est une frontière de
sécurité délibérée : ce projet tourne dans les pipelines CI d'autres gens, donc
« laissons les clients écrire du code qui s'exécute ici » n'est pas un compromis
à prendre pour une commodité.

**Voir aussi le défaut connu de `parser.cty_value_to_string`**, qui fait qu'une
règle `negate: true` sur un attribut valant un objet se déclenche à tort.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import yaml

from .parser import Attribute, Resource
from .report.finding import Finding, Severity
from .rules import FileInput
from .schema import KnowledgeBase

VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})


class CustomRuleError(ValueError):
    """Un jeu de règles personnalisées qui n'a pas pu être analysé ou validé.

    Bruyant par choix : une faute de frappe dans la configuration d'une
    organisation doit faire échouer le scan plutôt que de ne rien détecter en
    silence.
    """


@dataclass(slots=True)
class Rule:
    """Une règle de détection personnalisée, telle qu'écrite en YAML."""

    id: str = ""
    #: Type exact, ou « * » pour n'importe quelle ressource.
    resource_type: str = ""
    #: Type de bloc imbriqué où chercher (par exemple « ingress ») ; à omettre
    #: pour vérifier les attributs de premier niveau de la ressource.
    block: str = ""
    #: Nom de l'attribut à vérifier ; à omettre pour simplement signaler toute
    #: correspondance de resource_type et block.
    attribute: str = ""
    #: Expression régulière testée contre la valeur littérale de l'attribut.
    pattern: str = ""
    #: Signale quand le motif NE correspond PAS, ou que l'attribut est absent —
    #: pour les règles du type « doit avoir X ».
    negate: bool = False
    severity: str = ""
    message: str = ""

    compiled: re.Pattern[str] | None = field(default=None, repr=False)

    def validate(self) -> None:
        if not self.id:
            raise CustomRuleError("id is required")
        if not self.resource_type:
            raise CustomRuleError("resource_type is required")
        if self.severity not in VALID_SEVERITIES:
            raise CustomRuleError(
                f"severity must be one of low/medium/high/critical, got {self.severity!r}"
            )
        if not self.message:
            raise CustomRuleError("message is required")
        if not self.pattern and self.attribute:
            raise CustomRuleError(
                f"attribute {self.attribute!r} is set but pattern is empty — a pattern is "
                "required to evaluate the attribute's value (omit both to just flag the "
                "resource's/block's presence)"
            )
        if self.pattern:
            try:
                self.compiled = re.compile(self.pattern)
            except re.error as exc:
                raise CustomRuleError(f"invalid pattern: {exc}") from exc

    def check(self, path: str, res: Resource) -> list[Finding]:
        if self.resource_type != "*" and self.resource_type != res.type:
            return []

        if self.block:
            findings: list[Finding] = []
            for b in res.blocks:
                if b.type != self.block:
                    continue
                f = self._check_attrs(path, res, b.attributes, b.range.start.line)
                if f is not None:
                    findings.append(f)
            return findings

        f = self._check_attrs(path, res, res.attributes, res.def_range.start.line)
        return [f] if f is not None else []

    def _check_attrs(
        self,
        path: str,
        res: Resource,
        attrs: dict[str, Attribute],
        fallback_line: int,
    ) -> Finding | None:
        """Évalue une règle contre un jeu d'attributs : soit ceux de premier
        niveau d'une ressource, soit ceux d'un bloc imbriqué."""
        line = fallback_line
        matched = False

        if not self.attribute:
            # Aucun attribut précisé : cette règle signale la simple présence
            # de la ressource ou du bloc — par exemple « n'utilisez pas
            # aws_iam_user, utilisez aws_iam_role ».
            matched = True
        else:
            attribute = attrs.get(self.attribute)
            if attribute is not None and attribute.is_literal and self.compiled is not None:
                line = attribute.range.start.line
                matched = bool(self.compiled.search(attribute.raw_value)) != self.negate
            elif attribute is not None and not self.negate:
                # L'attribut existe mais n'est pas un littéral que l'on peut
                # comparer à un motif — c'est une variable ou une expression.
                # On ne peut pas l'évaluer, donc on ne devine pas.
                matched = False
            elif attribute is None:
                # Un attribut absent ne « correspond » que pour une règle
                # niée, c'est-à-dire « cet attribut doit être présent et
                # correspondre au motif ».
                matched = self.negate

        if not matched:
            return None

        return Finding(
            file=path,
            line=line,
            # Les découvertes personnalisées sont rapportées sous
            # `custom:<id de règle>`. `Category` est une énumération fermée des
            # catégories que les packs de règles documentent, et un identifiant
            # personnalisé n'en fait par définition pas partie : une chaîne
            # simple est donc passée — exactement ce que le type ouvert
            # `report.Category` de Go contient ici. Tout l'aval traite une
            # catégorie comme du texte : le mécanisme d'exclusion la compare,
            # les rendus l'affichent.
            category="custom:" + self.id,
            # Même forme que la catégorie : un nom de règle sur mesure doit
            # être impossible à confondre avec celui d'une règle du pack.
            rule_name="custom:" + self.id,
            severity=Severity(self.severity),
            resource=res.address(),
            message=self.message,
        )


@dataclass(slots=True)
class Config:
    """Un jeu complet de règles personnalisées, tel que chargé depuis la
    configuration YAML d'une organisation."""

    rules: list[Rule] = field(default_factory=list)

    def check(self, in_: FileInput, kb: KnowledgeBase | None) -> list[Finding]:
        """Adapte la configuration en une `rules.Rule`, pour qu'elle entre
        directement dans le même moteur que toute règle intégrée."""
        findings: list[Finding] = []
        for res in in_.head_resources:
            for r in self.rules:
                findings.extend(r.check(in_.path, res))
        return findings

    def as_engine_rule(self) -> Config:
        """Conservé par symétrie avec l'API Go ; `Config` satisfait déjà le
        protocole de règle."""
        return self


def load(data: bytes | str) -> Config:
    """Analyse et valide un jeu de règles personnalisées.

    Chaque règle est validée au chargement — sévérité valide, expression
    régulière valide, champs obligatoires présents — pour qu'une faute de frappe
    dans la configuration d'une organisation fasse échouer le scan bruyamment
    plutôt que de ne rien détecter en silence.
    """
    try:
        raw = yaml.safe_load(data)
    except yaml.YAMLError as exc:
        raise CustomRuleError(f"parsing custom rules: {exc}") from exc

    if raw is None:
        return Config()
    if not isinstance(raw, dict):
        raise CustomRuleError("custom rules: top level is not a mapping")

    config = Config()
    for i, entry in enumerate(raw.get("custom_rules") or []):
        if not isinstance(entry, dict):
            raise CustomRuleError(f"custom rule {i}: not a mapping")
        rule = Rule(
            id=str(entry.get("id", "")),
            resource_type=str(entry.get("resource_type", "")),
            block=str(entry.get("block", "")),
            attribute=str(entry.get("attribute", "")),
            pattern=str(entry.get("pattern", "")),
            negate=bool(entry.get("negate", False)),
            severity=str(entry.get("severity", "")),
            message=str(entry.get("message", "")),
        )
        try:
            rule.validate()
        except CustomRuleError as exc:
            raise CustomRuleError(f"custom rule {i}: {exc}") from exc
        config.rules.append(rule)
    return config
