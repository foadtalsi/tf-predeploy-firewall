"""Les traversées — la forme de référence `var.db_password` / `local.admin_pw`.

Une traversée est un nom racine suivi d'étapes d'attribut et d'index. Deux
choses en dépendent dans le scanner :

  * **La résolution de portée.** `parser.build_scope` collecte les `locals` et
    les valeurs par défaut de `variable` dans un contexte d'évaluation, et une
    traversée est ce qui en relit une valeur. C'est la machinerie derrière la
    détection d'un mot de passe situé à une indirection de distance, dans la
    valeur par défaut d'une variable.

  * **Le `resolved_from` d'une découverte.** Quand une valeur a été atteinte via
    une référence, la découverte le dit : « se résout en une chaîne littérale en
    dur (via var.db_password) ». Sans cela, un rapport pointant sur une ligne
    qui lit `password = var.db_password` ressemble à un faux positif pour
    quiconque ouvre la PR.
"""

from __future__ import annotations

from dataclasses import dataclass

from .diagnostics import Diagnostics, error
from .pos import Range
from .values import DYNAMIC_VAL, NUMBER, STRING, Value

#: Shared zero Range. Frozen and immutable, so one instance is safe as a
#: dataclass default and avoids a fresh allocation per traversal step.
NO_RANGE = Range()


@dataclass(frozen=True, slots=True)
class TraverseRoot:
    name: str
    range: Range = NO_RANGE


@dataclass(frozen=True, slots=True)
class TraverseAttr:
    name: str
    range: Range = NO_RANGE


@dataclass(frozen=True, slots=True)
class TraverseIndex:
    key: Value
    range: Range = NO_RANGE


Step = TraverseRoot | TraverseAttr | TraverseIndex


class Traversal(list[Step]):
    """Une référence, sous forme de liste d'étapes. La première est toujours un
    TraverseRoot pour une traversée absolue — la seule sorte que le scanner
    construit."""

    @property
    def root_name(self) -> str:
        if self and isinstance(self[0], TraverseRoot):
            return self[0].name
        return ""

    @property
    def range(self) -> Range:
        if not self:
            return Range()
        out = self[0].range
        for step in self[1:]:
            out = out.merge(step.range)
        return out

    def render(self, max_steps: int = 2) -> str:
        """Rend en texte source — « var.db_password », « local.settings ».

        S'arrête après `max_steps` étapes, parce que la partie utile d'une
        référence, pour un humain qui lit une découverte, est sa tête.
        `var.config.db.password` se rend en `var.config` : le lecteur a besoin
        de savoir quelle variable ouvrir, pas qu'on lui répète tout le chemin.
        """
        parts: list[str] = []
        for i, step in enumerate(self):
            if isinstance(step, TraverseRoot):
                parts.append(step.name)
            elif isinstance(step, TraverseAttr):
                parts.append("." + step.name)
            else:
                # An index or a splat: the root is still the useful part, and
                # rendering `[0]` into a message adds nothing a reader can act
                # on. Matches firstTraversalName's `default:` branch.
                pass
            if i > max_steps - 1:
                break
        return "".join(parts)

    def traverse(self, ctx: EvalContext | None) -> tuple[Value, Diagnostics]:
        """Résout contre une portée, ou échoue proprement.

        L'échec est le cas ordinaire : sans contexte, ou pour une référence vers
        quoi que ce soit que la portée ne détient pas — un attribut de
        ressource, une variable sans valeur par défaut, une valeur venue d'un
        .tfvars — ceci rend une erreur et l'appelant saute l'attribut. Deviner
        ici est par où entre un faux positif.
        """
        if not self:
            return DYNAMIC_VAL, error("Invalid traversal", "Empty reference.")
        root = self[0]
        if not isinstance(root, TraverseRoot):
            return DYNAMIC_VAL, error("Invalid traversal", "Reference has no root.", self.range)
        if ctx is None:
            return DYNAMIC_VAL, error(
                "Variables not allowed",
                "Variables may not be used here.",
                root.range,
            )

        current = ctx.lookup(root.name)
        if current is None:
            return DYNAMIC_VAL, error(
                "Unknown variable",
                f"There is no variable named {root.name!r}.",
                root.range,
            )

        for step in self[1:]:
            if current.is_null() or current.is_unknown():
                return DYNAMIC_VAL, error(
                    "Unresolvable reference", "Value is not statically known.", step.range
                )
            if isinstance(step, TraverseAttr):
                if not isinstance(current.raw, dict) or step.name not in current.raw:
                    return DYNAMIC_VAL, error(
                        "Unsupported attribute",
                        f"This value has no attribute named {step.name!r}.",
                        step.range,
                    )
                current = current.raw[step.name]
            elif isinstance(step, TraverseIndex):
                current = _index(current, step)
                if current is None:
                    return DYNAMIC_VAL, error(
                        "Invalid index", "This value cannot be indexed.", step.range
                    )
        return current, Diagnostics()


def _index(collection: Value, step: TraverseIndex) -> Value | None:
    key = step.key
    raw = collection.raw
    if isinstance(raw, tuple):
        if key.type is not NUMBER:
            return None
        i = int(key.as_decimal())
        if i < 0 or i >= len(raw):
            return None
        element: Value = raw[i]
        return element
    if isinstance(raw, dict):
        if key.type is not STRING:
            return None
        entry: Value | None = raw.get(key.as_string())
        return entry
    return None


class EvalContext:
    """Une portée pour résoudre des traversées.

    À l'image de hcl.EvalContext, moins la table de fonctions. Cette omission
    est délibérée et porteuse : le scanner ne fournit jamais de fonctions, donc
    `jsonencode({...})` reste inévaluable — ce qui est précisément pourquoi
    `rules.iam_wildcard` lit la plage de source brute plutôt que la valeur.
    Ajoutez ici une table de fonctions et cette règle change silencieusement de
    comportement.
    """

    __slots__ = ("parent", "variables")

    def __init__(
        self, variables: dict[str, Value] | None = None, parent: EvalContext | None = None
    ) -> None:
        self.variables: dict[str, Value] = variables or {}
        self.parent = parent

    def lookup(self, name: str) -> Value | None:
        ctx: EvalContext | None = self
        while ctx is not None:
            if name in ctx.variables:
                return ctx.variables[name]
            ctx = ctx.parent
        return None

    def child(self, variables: dict[str, Value]) -> EvalContext:
        return EvalContext(variables, parent=self)
