"""Charge les packs de règles : la surface d'arguments valides de chaque type de
ressource, ses arguments ForceNew, s'il est porteur d'état, et son prix
approximatif — sans plan, sans état et sans identifiants.

Port de internal/schema/loader.go et docs.go.

Les packs sont des fichiers de données générés (voir `tfpdf.genpack`). Le
scanner embarque un pack de base et peut y superposer un pack plus large
récupéré au moment du scan ; les deux viennent de la même version du
fournisseur, donc la superposition ne contredit jamais la base.

Plus rien ici n'est écrit à la main par type de ressource. Les listes curées que
ceci remplace donnaient 29 arguments à `aws_instance` là où le fournisseur en
déclare 71, et chaque argument manquant devenait une fausse découverte
« attribut halluciné » — en sévérité haute, donc bloquante.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field
from importlib import resources
from typing import IO, Any

#: The on-disk pack layout this build understands. A pack declaring a newer
#: version is rejected rather than half-read: a pack is security-relevant data,
#: and silently ignoring fields we don't recognise could turn a blocking
#: finding into a missed one.
PACK_FORMAT_VERSION = 1

#: Maps a provider's short name to its Terraform Registry namespace. Unlisted
#: providers fall back to hashicorp/<name>, which is right for the official
#: ones and produces a link that 404s rather than a wrong one for anything else.
REGISTRY_NAMESPACE = {
    "aws": "hashicorp",
    "azurerm": "hashicorp",
}


class PackError(ValueError):
    """Un pack qui n'a pas pu être lu."""


@dataclass(slots=True)
class ForceNewSpec:
    """Quels arguments — de premier niveau ou de bloc imbriqué — déclenchent une
    destruction-recréation pour un type de ressource."""

    top_level: list[str] = field(default_factory=list)
    #: Block path -> ForceNew argument names inside it.
    nested_blocks: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class ResourceSchema:
    """Les arguments valides d'un type de ressource, au premier niveau comme à
    l'intérieur des blocs imbriqués."""

    #: Valid top-level argument names, including nested block names and
    #: Terraform's own meta-arguments.
    top_level: list[str] = field(default_factory=list)
    #: Block path -> valid argument names inside it. Paths absent from this map
    #: are not validated, so an unrecognised block can never produce a finding.
    nested_blocks: dict[str, list[str]] = field(default_factory=dict)


@dataclass(slots=True)
class PricingSpec:
    """Le coût mensuel approximatif curé pour un type de ressource.

    Un type peut avoir un coût forfaitaire `base`, et/ou un coût dépendant de
    la valeur d'un unique attribut moteur de prix (`attribute`, par exemple
    instance_type). Un raté dans `by_attribute` retombe sur `default`. Tous les
    chiffres sont des estimations grossières en dollars par mois.
    """

    #: Flat monthly cost regardless of arguments.
    base: float = 0.0
    #: Argument whose value drives cost, if any.
    attribute: str = ""
    #: Argument value -> monthly cost.
    by_attribute: dict[str, float] = field(default_factory=dict)
    #: Used when `attribute` is set but the value is not in `by_attribute`.
    default: float = 0.0

    def monthly_cost(self, attr_value: str) -> float:
        """Le coût mensuel estimé en dollars, pour une valeur d'argument donnée.

        Le coût de base et le coût piloté par l'attribut s'additionnent, ce qui
        couvre une ressource ayant à la fois un forfait et un prix à la taille.
        """
        cost = self.base
        if self.attribute:
            cost += self.by_attribute.get(attr_value, self.default)
        return cost


@dataclass(slots=True)
class _PackResource:
    """L'entrée d'un type de ressource telle qu'elle apparaît sur disque.

    Décodée paresseusement : le pack AWS complet fait environ 14 Mo de JSON
    couvrant quelque 1700 types, et un scan n'en touche typiquement que
    quelques dizaines. Garder l'entrée brute et décoder à la demande garde le
    coût proportionnel au dépôt scanné plutôt qu'à la taille du pack.
    """

    top_level: list[str] = field(default_factory=list)
    nested_blocks: dict[str, list[str]] = field(default_factory=dict)
    force_new_top_level: list[str] = field(default_factory=list)
    force_new_nested: dict[str, list[str]] = field(default_factory=dict)
    critical: bool = False
    pricing: PricingSpec | None = None


class _LoadedPack:
    """Un pack analysé : ses métadonnées, plus des entrées de ressources encore
    non décodées."""

    __slots__ = ("_decoded", "format_version", "id", "provider", "provider_version", "resources")

    def __init__(self, doc: dict[str, Any]) -> None:
        self.format_version: int = int(doc.get("format_version", 0) or 0)
        self.id: str = str(doc.get("id", ""))
        self.provider: str = str(doc.get("provider", ""))
        self.provider_version: str = str(doc.get("provider_version", ""))
        self.resources: dict[str, Any] = doc.get("resources") or {}
        self._decoded: dict[str, _PackResource | None] = {}

    def resource(self, r_type: str) -> _PackResource | None:
        if r_type in self._decoded:
            return self._decoded[r_type]
        raw = self.resources.get(r_type)
        if raw is None:
            return None
        try:
            r = _decode_resource(raw)
        except (TypeError, ValueError, AttributeError):
            # A malformed entry means this type is simply unknown to us. It
            # must not take down a scan that has nothing to do with it.
            self._decoded[r_type] = None
            return None
        self._decoded[r_type] = r
        return r


def _decode_resource(raw: Any) -> _PackResource:
    if not isinstance(raw, dict):
        raise TypeError("resource entry is not an object")
    pricing_raw = raw.get("pricing")
    pricing = None
    if isinstance(pricing_raw, dict):
        pricing = PricingSpec(
            base=float(pricing_raw.get("base", 0.0) or 0.0),
            attribute=str(pricing_raw.get("attribute", "") or ""),
            by_attribute={
                str(k): float(v) for k, v in (pricing_raw.get("by_attribute") or {}).items()
            },
            default=float(pricing_raw.get("default", 0.0) or 0.0),
        )
    return _PackResource(
        top_level=list(raw.get("top_level") or []),
        nested_blocks={k: list(v) for k, v in (raw.get("nested_blocks") or {}).items()},
        force_new_top_level=list(raw.get("force_new_top_level") or []),
        force_new_nested={k: list(v) for k, v in (raw.get("force_new_nested") or {}).items()},
        critical=bool(raw.get("critical", False)),
        pricing=pricing,
    )


@dataclass(slots=True, frozen=True)
class ProviderCoverage:
    """La part d'un fournisseur dans une couverture."""

    name: str
    version: str


@dataclass(slots=True)
class Coverage:
    """Ce que les packs chargés savent — pour l'en-tête du scan, et pour les
    questions de support de la forme « pourquoi n'a-t-il pas attrapé ça ? »."""

    #: The loaded pack IDs, sorted.
    packs: list[str] = field(default_factory=list)
    #: Each covered provider with the release its outermost pack describes,
    #: sorted by name. Per provider, not global: the single provider_version
    #: field this replaces was silently overwritten by whichever pack loaded
    #: last, which was already wrong the moment a second provider's pack sat
    #: next to the first.
    providers: list[ProviderCoverage] = field(default_factory=list)
    #: The number of distinct types across all loaded packs.
    resource_types: int = 0
    #: Whether anything is overlaid on the embedded packs.
    extended: bool = False

    def version_of(self, provider: str) -> str:
        """La version du fournisseur que les packs décrivent, ou « » si aucun ne la
        couvre."""
        for p in self.providers:
            if p.name == provider:
                return p.version
        return ""


class KnowledgeBase:
    """Les packs chargés, éventuellement pour plusieurs fournisseurs à la fois.

    Les types de ressources sont naturellement cloisonnés par leur préfixe
    (aws_db_instance, azurerm_mssql_server), donc les recherches n'ont besoin
    d'aucun routage par fournisseur : les packs sont simplement consultés dans
    l'ordre de chargement inverse. À construire avec `load` ou `load_with`.
    """

    __slots__ = ("_embedded", "_packs")

    def __init__(self, packs: list[_LoadedPack] | None = None, embedded: int = 0) -> None:
        #: Consulted last-first, so a pack overlaid at scan time takes
        #: precedence over an embedded base pack for any type they share.
        self._packs: list[_LoadedPack] = packs or []
        #: How many of those packs shipped inside the distribution, so
        #: `coverage` can tell "extended" apart from "free tier" without caring
        #: how many base packs the free tier happens to contain.
        self._embedded = embedded

    # --- lookups ----------------------------------------------------------

    def _lookup(self, r_type: str) -> _PackResource | None:
        for p in reversed(self._packs):
            r = p.resource(r_type)
            if r is not None:
                return r
        return None

    def resource_schema(self, r_type: str) -> ResourceSchema | None:
        """La surface d'arguments valides d'un type de ressource.

        Les types que ne couvre aucun pack chargé rendent None, et la règle des
        arguments inconnus les saute entièrement : sous-détecter est toujours
        préférable à signaler du Terraform valide.
        """
        r = self._lookup(r_type)
        if r is None or not r.top_level:
            return None
        return ResourceSchema(top_level=r.top_level, nested_blocks=r.nested_blocks)

    def force_new(self, r_type: str) -> ForceNewSpec | None:
        """Les arguments ForceNew d'un type de ressource."""
        r = self._lookup(r_type)
        if r is None or (not r.force_new_top_level and not r.force_new_nested):
            return None
        return ForceNewSpec(top_level=r.force_new_top_level, nested_blocks=r.force_new_nested)

    def is_critical(self, r_type: str) -> bool:
        """Dit si détruire ce type de ressource perd des données, et donc s'il est
        censé porter lifecycle { prevent_destroy = true }."""
        r = self._lookup(r_type)
        return r is not None and r.critical

    def pricing_for(self, r_type: str) -> PricingSpec | None:
        """La spécification de coût mensuel approximatif d'un type de ressource.

        Les types qui n'en ont pas contribuent 0 $ à une estimation, plutôt
        qu'une supposition.
        """
        r = self._lookup(r_type)
        if r is None or r.pricing is None:
            return None
        return r.pricing

    def coverage(self) -> Coverage:
        seen: set[str] = set()
        versions: dict[str, str] = {}

        c = Coverage(extended=len(self._packs) > self._embedded)
        for p in self._packs:
            c.packs.append(p.id)
            # Later packs overlay earlier ones, so the last version recorded
            # per provider is the one lookups actually resolve against.
            versions[p.provider] = p.provider_version
            seen.update(p.resources)

        c.providers = sorted(
            (ProviderCoverage(name=n, version=v) for n, v in versions.items()),
            key=lambda p: p.name,
        )
        c.resource_types = len(seen)
        c.packs.sort()
        return c

    # --- documentation links ---------------------------------------------

    def _pack_for(self, r_type: str) -> _LoadedPack | None:
        """Le pack d'où un type de ressource a été résolu, pour qu'un lien de
        documentation porte la version de fournisseur que ce pack décrit
        réellement — un pack étendu superposé et le pack de base embarqué
        pouvant être construits depuis des versions différentes.
        """
        for p in reversed(self._packs):
            if p.resource(r_type) is not None:
                return p
        return None

    def doc_url(self, r_type: str, data_source: bool = False) -> str:
        """La page de documentation du Terraform Registry pour un type de
        ressource, ou « » quand aucun pack chargé ne le couvre.

        L'URL épingle la version du fournisseur depuis laquelle le pack a été
        généré, au lieu de pointer sur « latest ». Une découverte affirme qu'un
        argument n'existe pas ; la page qui étaye cette affirmation doit être
        la version du fournisseur contre laquelle le scanner a vérifié, sinon
        la première chose qu'un lecteur sceptique trouve est une page de doc en
        désaccord avec l'outil, pour des raisons qu'aucun des deux n'explique.

        À noter : les packs ne décrivent que des types de ressources. Une
        source de données dont le nom n'a pas d'équivalent en ressource —
        aws_availability_zones, aws_caller_identity — n'obtient donc aucun
        lien, même si sa page de documentation existe. Deviner l'URL depuis le
        nom du type marcherait la plupart du temps, et le reste du temps
        enverrait quelqu'un sur un 404 pour vérifier une affirmation ; un lien
        absent est le moindre échec.
        """
        pack = self._pack_for(r_type)
        if pack is None:
            return ""

        namespace = REGISTRY_NAMESPACE.get(pack.provider, "hashicorp")
        version = pack.provider_version or "latest"

        # Registry doc slugs drop the provider prefix: aws_db_instance is
        # documented at .../docs/resources/db_instance.
        prefix = pack.provider + "_"
        slug = r_type[len(prefix) :] if r_type.startswith(prefix) else r_type
        section = "data-sources" if data_source else "resources"

        return (
            f"https://registry.terraform.io/providers/{namespace}/{pack.provider}/"
            f"{version}/docs/{section}/{slug}"
        )


def parse_pack(fp: IO[bytes] | bytes) -> _LoadedPack:
    """Lit un pack compressé en gzip."""
    raw = fp if isinstance(fp, bytes) else fp.read()
    try:
        decompressed = gzip.decompress(raw)
    except (OSError, EOFError) as exc:
        raise PackError(f"pack is not gzip: {exc}") from exc
    try:
        doc = json.loads(decompressed)
    except json.JSONDecodeError as exc:
        raise PackError(f"decoding pack: {exc}") from exc
    if not isinstance(doc, dict):
        raise PackError("pack is not an object")

    pack = _LoadedPack(doc)
    if pack.format_version != PACK_FORMAT_VERSION:
        raise PackError(
            f"pack {pack.id!r} has format version {pack.format_version}, this build "
            f"understands {PACK_FORMAT_VERSION} — upgrade the scanner"
        )
    return pack


def load() -> KnowledgeBase:
    """La base de connaissances construite à partir des seuls packs de base
    embarqués — l'offre gratuite, et le repli chaque fois qu'aucun pack étendu
    n'est disponible.

    Chaque pack de base sous `data/` est livré avec la distribution, un par
    fournisseur que l'offre gratuite couvre. Ajouter un fournisseur à l'offre
    gratuite est donc un changement de données — déposer
    pack_<fournisseur>_base.json.gz dans data/ — et non un changement de code.
    """
    packs: list[_LoadedPack] = []
    data_dir = resources.files(__package__).joinpath("data")
    names = sorted(p.name for p in data_dir.iterdir() if p.name.endswith(".json.gz"))
    for name in names:
        try:
            packs.append(parse_pack(data_dir.joinpath(name).read_bytes()))
        except PackError as exc:
            # A shipped pack that doesn't parse is a broken build, not a
            # degraded one — it was checked in, so fail loudly at load rather
            # than quietly scanning with a provider missing.
            raise PackError(f"loading shipped pack {name}: {exc}") from exc
    if not packs:
        raise PackError("no shipped rule packs — broken build")
    return KnowledgeBase(packs=packs, embedded=len(packs))


def load_with(*extra: IO[bytes] | bytes) -> tuple[KnowledgeBase, list[Exception]]:
    """La base de connaissances avec des packs supplémentaires superposés aux
    packs de base embarqués, dans l'ordre donné.

    Un pack qui échoue à l'analyse est signalé mais n'empêche pas le
    chargement : perdre un pack étendu doit dégrader la couverture, jamais
    casser la CI d'un client.
    """
    errs: list[Exception] = []
    kb = load()
    for r in extra:
        try:
            kb._packs.append(parse_pack(r))
        except PackError as exc:
            errs.append(exc)
    return kb, errs
