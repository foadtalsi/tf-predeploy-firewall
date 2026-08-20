"""Le modèle de valeurs — port fidèle et délibérément partiel de go-cty.

Surface utilisée, tout le reste étant absent exprès plutôt qu'oublié :

    v.type == STRING / BOOL / NUMBER      tests de nature littérale
    v.type.is_list/set/tuple/map/object   tests de nature de collection
    v.is_null(), v.is_wholly_known()      les deux gardes que chaque règle pose
    v.as_string(), v.true(), v.as_number_string()
    v.as_value_map(), v.as_value_slice(), v.element_iterator()
    object_val(mapping)                   remise d'une portée à l'évaluateur

**Inconnu n'est pas None.** cty distingue « valeur nulle » de « valeur non
connaissable statiquement ». Les fondre ferait ressembler chaque `var.x`
irrésoluble à un nul explicite, et les règles qui jugent les valeurs *écrites*
se déclencheraient sur des valeurs que personne n'a écrites. D'où `UNKNOWN`
comme sentinelle et `is_wholly_known()` qui descend dans les collections.

**Les nombres sont exacts** — `Decimal`, pas `float`, pour qu'un littéral `10`
ne s'affiche pas `10.0` et ne change pas le texte que les règles comparent.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any


class Kind(Enum):
    STRING = "string"
    NUMBER = "number"
    BOOL = "bool"
    LIST = "list"
    SET = "set"
    TUPLE = "tuple"
    MAP = "map"
    OBJECT = "object"
    DYNAMIC = "dynamic"


@dataclass(frozen=True, slots=True)
class Type:
    """Le type d'une valeur.

    Les types d'éléments ne sont pas suivis : aucune règle du scanner ne les
    inspecte, et les porter demanderait d'implémenter l'unification de types de
    cty pour aucun lecteur.
    """

    kind: Kind

    def is_primitive(self) -> bool:
        return self.kind in (Kind.STRING, Kind.NUMBER, Kind.BOOL)

    def is_list_type(self) -> bool:
        return self.kind is Kind.LIST

    def is_set_type(self) -> bool:
        return self.kind is Kind.SET

    def is_tuple_type(self) -> bool:
        return self.kind is Kind.TUPLE

    def is_map_type(self) -> bool:
        return self.kind is Kind.MAP

    def is_object_type(self) -> bool:
        return self.kind is Kind.OBJECT

    def is_collection_type(self) -> bool:
        return self.kind in (Kind.LIST, Kind.SET, Kind.TUPLE, Kind.MAP, Kind.OBJECT)

    def __str__(self) -> str:
        return self.kind.value


STRING = Type(Kind.STRING)
NUMBER = Type(Kind.NUMBER)
BOOL = Type(Kind.BOOL)
LIST = Type(Kind.LIST)
SET = Type(Kind.SET)
TUPLE = Type(Kind.TUPLE)
MAP = Type(Kind.MAP)
OBJECT = Type(Kind.OBJECT)
DYNAMIC = Type(Kind.DYNAMIC)


class _Unknown:
    """Sentinelle pour une valeur qui existe mais ne peut pas être déterminée
    statiquement."""

    _instance: _Unknown | None = None

    def __new__(cls) -> _Unknown:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "<unknown>"


_UNKNOWN_MARKER = _Unknown()


@dataclass(frozen=True, slots=True)
class Value:
    """Une valeur immuable, dans le style de cty.

    `raw` contient : un `str` pour STRING, un `Decimal` pour NUMBER, un `bool`
    pour BOOL, un `tuple[Value, ...]` pour les natures de séquence, un
    `dict[str, Value]` pour les natures de correspondance, `None` pour un nul,
    et `_UNKNOWN_MARKER` pour un inconnu.
    """

    type: Type
    raw: Any = None

    # --- state predicates -------------------------------------------------

    def is_null(self) -> bool:
        return self.raw is None

    def is_unknown(self) -> bool:
        return self.raw is _UNKNOWN_MARKER

    def is_wholly_known(self) -> bool:
        """Faux si cette valeur, ou quoi que ce soit d'imbriqué dedans, est
        inconnu.

        Une liste contenant un élément irrésoluble n'est pas utilisable comme
        littéral, donc l'ensemble doit se déclarer inconnu — sinon une règle
        jugerait une valeur partielle comme si elle était complète.
        """
        if self.is_unknown():
            return False
        if self.is_null():
            return True
        if isinstance(self.raw, tuple):
            return all(v.is_wholly_known() for v in self.raw)
        if isinstance(self.raw, dict):
            return all(v.is_wholly_known() for v in self.raw.values())
        return True

    # --- accessors --------------------------------------------------------

    def as_string(self) -> str:
        if self.type is not STRING or not isinstance(self.raw, str):
            raise TypeError(f"as_string on a {self.type} value")
        return self.raw

    def true(self) -> bool:
        if self.type is not BOOL or not isinstance(self.raw, bool):
            raise TypeError(f"true() on a {self.type} value")
        return self.raw

    def as_decimal(self) -> Decimal:
        if self.type is not NUMBER or not isinstance(self.raw, Decimal):
            raise TypeError(f"as_decimal on a {self.type} value")
        return self.raw

    def as_number_string(self) -> str:
        """Rend un nombre comme le fait le `big.Float.String()` de Go, ce que le
        scanner Go écrit dans `Attribute.RawValue`.

        C'est-à-dire `Text('g', 10)` : notation décimale simple pour les ordres
        de grandeur ordinaires, pas de `.0` final sur un entier, et notation
        scientifique au-delà de 10 chiffres significatifs. Cette dernière clause
        est inatteignable pour les valeurs que Terraform porte réellement —
        ports, tailles, décomptes, jours de rétention — mais elle est
        implémentée plutôt qu'écartée par hypothèse, parce qu'une divergence
        silencieuse dans une règle de comparaison de valeurs est le genre de bug
        qui se manifeste comme une découverte manquante des mois plus tard.
        """
        return format_number(self.as_decimal())

    def as_value_slice(self) -> tuple[Value, ...]:
        if not isinstance(self.raw, tuple):
            raise TypeError(f"as_value_slice on a {self.type} value")
        return self.raw

    def as_value_map(self) -> dict[str, Value]:
        if not isinstance(self.raw, dict):
            raise TypeError(f"as_value_map on a {self.type} value")
        return dict(self.raw)

    def element_iterator(self) -> Iterator[tuple[Value, Value]]:
        """Produit des paires (clé, élément), à l'image de l'ElementIterator de
        cty.

        Les clés de séquence sont leur indice entier sous forme de valeur
        NUMBER ; les clés de correspondance sont des valeurs STRING. Les clés de
        correspondance sont produites triées, comme le fait cty, pour que tout
        ce qui est construit en itérant une valeur soit déterministe : les tests
        sur fichiers de référence en dépendent.
        """
        if isinstance(self.raw, tuple):
            for i, v in enumerate(self.raw):
                yield number_val(i), v
        elif isinstance(self.raw, dict):
            for k in sorted(self.raw):
                yield string_val(k), self.raw[k]

    def __str__(self) -> str:
        if self.is_unknown():
            return "<unknown>"
        if self.is_null():
            return "<null>"
        if self.type is STRING:
            return repr(self.raw)
        if self.type is NUMBER:
            return self.as_number_string()
        if self.type is BOOL:
            return "true" if self.raw else "false"
        return repr(self.raw)


def format_number(d: Decimal) -> str:
    """Sémantique de `big.Float.String()` / `Text('g', 10)` de Go, pour un
    Decimal."""
    if d == d.to_integral_value() and abs(d) < Decimal(10) ** 10:
        # Integers render bare: 3306, not 3306.0 and not 3.306e+03.
        return str(int(d))
    formatted = f"{d:.10g}"
    # Python writes e-05 / e+12; Go writes the same, but normalises a lone
    # "e+00" away. Strip an exponent of zero rather than emit it.
    if formatted.endswith(("e+00", "e-00")):
        formatted = formatted[:-4]
    return formatted


# --- constructors --------------------------------------------------------


def string_val(s: str) -> Value:
    return Value(STRING, s)


def number_val(n: int | float | Decimal | str) -> Value:
    if isinstance(n, Decimal):
        return Value(NUMBER, n)
    try:
        return Value(NUMBER, Decimal(str(n)))
    except InvalidOperation as exc:  # pragma: no cover - guarded by the lexer
        raise ValueError(f"not a number: {n!r}") from exc


def bool_val(b: bool) -> Value:
    return Value(BOOL, bool(b))


def tuple_val(elements: Sequence[Value]) -> Value:
    return Value(TUPLE, tuple(elements))


def list_val(elements: Sequence[Value]) -> Value:
    return Value(LIST, tuple(elements))


def set_val(elements: Sequence[Value]) -> Value:
    return Value(SET, tuple(elements))


def object_val(attrs: Mapping[str, Value]) -> Value:
    return Value(OBJECT, dict(attrs))


def map_val(entries: Mapping[str, Value]) -> Value:
    return Value(MAP, dict(entries))


def null_val(t: Type = DYNAMIC) -> Value:
    return Value(t, None)


def unknown_val(t: Type = DYNAMIC) -> Value:
    return Value(t, _UNKNOWN_MARKER)


#: A value that is present but unknowable — what every unresolvable reference
#: evaluates to.
DYNAMIC_VAL = unknown_val(DYNAMIC)

#: The null literal.
NULL_VAL = null_val(DYNAMIC)

TRUE = bool_val(True)
FALSE = bool_val(False)
EMPTY_STRING = string_val("")


# --- conversions ---------------------------------------------------------


def to_string(v: Value) -> tuple[str, bool]:
    """Convertit en chaîne comme le fait l'interpolation de template de HCL :
    les chaînes passent telles quelles, les nombres et booléens prennent leur
    écriture canonique, tout le reste échoue. Rend (texte, ok)."""
    if v.is_null() or v.is_unknown():
        return "", False
    if v.type is STRING:
        return v.as_string(), True
    if v.type is NUMBER:
        return v.as_number_string(), True
    if v.type is BOOL:
        return ("true" if v.true() else "false"), True
    return "", False


def from_python(obj: Any) -> Value:
    """Élève un objet Python issu d'un décodage JSON en une Value.

    Utilisé par le chemin .tfvars.json et par le lecteur de plan JSON, pour que
    les deux puissent remettre leurs valeurs au même code de jugement que le
    chemin HCL.
    """
    if obj is None:
        return NULL_VAL
    if isinstance(obj, bool):
        return bool_val(obj)
    if isinstance(obj, (int, float, Decimal)):
        return number_val(obj)
    if isinstance(obj, str):
        return string_val(obj)
    if isinstance(obj, Mapping):
        return object_val({str(k): from_python(v) for k, v in obj.items()})
    if isinstance(obj, Sequence):
        return tuple_val([from_python(v) for v in obj])
    return DYNAMIC_VAL
