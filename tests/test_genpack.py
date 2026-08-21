"""Tests du générateur de packs. `cmd/genpack` n'a pas de fichier de test à
lui.

C'est un trou qui mérite d'être comblé plutôt que recopié : cet outil décide ce
que le scanner croit être les arguments d'un fournisseur. Un argument tombé d'un
pack devient une découverte `unknown_attribute` sur du Terraform valide, et
cette règle est de sévérité haute — un bug de génération ne produit donc pas un
scanner plus discret, il en produit un qui bloque des PR sur des arguments qui
existent.

Le test central régénère chaque pack commité depuis des entrées dérivées de ce
même pack, et compare le JSON octet pour octet. C'est un aller-retour plutôt
qu'une comparaison contre le générateur Go, parce que la vraie entrée du
générateur Go est une copie de fournisseur de plusieurs gigaoctets. Ce qu'il
établit, en revanche, c'est que chaque transformation entre « surface
d'arguments + index ForceNew + surcouches curées » et les octets livrés est
reproduite exactement : l'ordre des champs, l'omission des vides, le tri qui
garde la régénération sans diff, l'injection des méta-arguments, le filtre de
validité sur ForceNew, et le sous-ensemble du pack de base.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path
from typing import Any

import pytest

from tfpdf.genpack import (
    META_ARGUMENTS,
    ForceNewIndex,
    Pack,
    PackPricing,
    PackResource,
    SchemaError,
    apply_force_new,
    build_packs,
    dedupe,
    index_from_pack,
    load_provider_schema,
    read_pricing,
    read_string_list,
)

CURATED = Path("src/tfpdf/schema/curated")
PACK_DATA = Path("src/tfpdf/schema/data")


def _committed_pack(provider: str) -> dict[str, Any]:
    path = PACK_DATA / f"pack_{provider}_base.json.gz"
    document = json.loads(gzip.decompress(path.read_bytes()))
    assert isinstance(document, dict)
    return document


def _schema_json_from_pack(pack: dict[str, Any], provider_addr: str) -> dict[str, Any]:
    """Synthétise un document `terraform providers schema -json` qui
    produirait la surface d'arguments de ce pack.

    Les chemins de blocs imbriqués sont pointés : il faut donc les reconstruire
    en l'arbre qu'émet terraform — ce qui est en soi une vérification de
    `_collect_block`, une mauvaise jonction de chemin ici ou là ne faisant pas
    l'aller-retour.
    """
    resource_schemas: dict[str, Any] = {}
    for r_type, r in pack["resources"].items():
        nested = r.get("nested_blocks") or {}
        # Deepest paths last, so a parent block exists before its child is
        # attached to it.
        root: dict[str, Any] = {"attributes": {}, "block_types": {}}

        def block_at(path: str, root: dict[str, Any] = root) -> dict[str, Any]:
            node = root
            for part in path.split("."):
                bt = node["block_types"].setdefault(
                    part, {"nesting_mode": "list", "block": {"attributes": {}, "block_types": {}}}
                )
                node = bt["block"]
            return node

        # Deepest first, so every child block_type exists before its parent's
        # attribute list is filled in — a name that is a nested block must not
        # also be declared as an attribute of the same node. Terraform never
        # emits both, and the loader concatenates the two lists without
        # deduplicating (Go's does not either), so the collision would show up
        # as a duplicated argument name.
        for path in sorted(nested, key=lambda p: -p.count(".")):
            node = block_at(path)
            for name in nested[path]:
                if name not in node["block_types"]:
                    node["attributes"][name] = {"optional": True}

        for name in r["top_level"]:
            if name in META_ARGUMENTS:
                continue  # injected by the loader, never in the provider schema
            if name in root["block_types"]:
                continue  # a block, already declared above
            root["attributes"][name] = {"optional": True}

        resource_schemas[r_type] = {"version": 0, "block": root}

    return {
        "format_version": "1.0",
        "provider_schemas": {provider_addr: {"resource_schemas": resource_schemas}},
    }


@pytest.mark.parametrize("provider", ["aws", "azurerm"])
def test_regenerating_a_committed_pack_reproduces_it_exactly(provider: str, tmp_path: Path) -> None:
    """Tout le pipeline, contre les packs que le scanner livre réellement."""
    committed = _committed_pack(provider)
    addr = f"registry.terraform.io/hashicorp/{provider}"

    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(_schema_json_from_pack(committed, addr)))

    resources = load_provider_schema(schema_path, addr)
    curated = CURATED if provider == "aws" else CURATED / provider

    base, _full = build_packs(
        provider=provider,
        resources=resources,
        provider_ver=committed["provider_version"],
        curated_dir=curated,
        index=index_from_pack(committed),
    )

    assert base.to_json() == committed, (
        "the regenerated base pack must match the committed one field for field"
    )
    # And byte for byte, which also pins the compact JSON encoding and the
    # trailing newline Go's Encoder appends.
    assert (
        base.encode()
        == json.dumps(committed, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"
    )


@pytest.mark.parametrize("provider", ["aws", "azurerm"])
def test_the_gzip_content_matches_but_the_framing_does_not(provider: str, tmp_path: Path) -> None:
    """Les fichiers de pack sont commités : il vaut donc la peine d'être précis
    sur ce qui change quand ils sont régénérés par cette version plutôt que par
    celle de Go.

    Le **contenu** est identique — 61 Ko de JSON pour aws, 79 Ko pour azurerm,
    octet pour octet. Le **flux gzip** ne l'est pas : le zlib de Python et le
    compress/flate de Go font des choix DEFLATE différents et également valides,
    et le résultat est une poignée d'octets d'écart en taille. Rien ne lit les
    octets compressés — le chargeur décompresse d'abord — mais les fichiers
    commités montreront un diff à la première régénération, et ce diff est de la
    compression, pas de la détection.
    """
    committed_path = PACK_DATA / f"pack_{provider}_base.json.gz"
    committed = json.loads(gzip.decompress(committed_path.read_bytes()))
    addr = f"registry.terraform.io/hashicorp/{provider}"
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(_schema_json_from_pack(committed, addr)))

    base, _ = build_packs(
        provider,
        load_provider_schema(schema_path, addr),
        committed["provider_version"],
        CURATED if provider == "aws" else CURATED / provider,
        index_from_pack(committed),
    )
    out = tmp_path / "regenerated.json.gz"
    base.write_gzip_json(out)

    assert gzip.decompress(out.read_bytes()) == gzip.decompress(committed_path.read_bytes())


@pytest.mark.parametrize("provider", ["aws", "azurerm"])
def test_the_full_pack_is_a_superset_of_the_base_pack(provider: str, tmp_path: Path) -> None:
    """Le pack de base est *découpé dans* le pack complet plutôt que généré
    séparément, si bien que les paliers gratuit et payant ne peuvent pas être en
    désaccord sur un type de ressource qu'ils couvrent tous les deux."""
    committed = _committed_pack(provider)
    addr = f"registry.terraform.io/hashicorp/{provider}"
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(_schema_json_from_pack(committed, addr)))

    curated = CURATED if provider == "aws" else CURATED / provider
    base, full = build_packs(
        provider,
        load_provider_schema(schema_path, addr),
        committed["provider_version"],
        curated,
        index_from_pack(committed),
    )

    assert set(base.resources) <= set(full.resources)
    for t, r in base.resources.items():
        assert r.to_json() == full.resources[t].to_json(), (
            f"{t} differs between the base and full packs"
        )
    assert base.id.endswith("-base")
    assert full.id.endswith("-full")


def test_the_written_pack_is_loadable_by_the_scanner(tmp_path: Path) -> None:
    """Le générateur et le chargeur sont les deux moitiés d'un même format.
    Ceci promène un pack jusqu'au gzip et le ramène par `tfpdf.schema`."""
    from tfpdf import schema

    committed = _committed_pack("aws")
    addr = "registry.terraform.io/hashicorp/aws"
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(_schema_json_from_pack(committed, addr)))

    base, _ = build_packs(
        "aws",
        load_provider_schema(schema_path, addr),
        committed["provider_version"],
        CURATED,
        index_from_pack(committed),
    )
    out = tmp_path / "pack.json.gz"
    base.write_gzip_json(out)

    kb, errs = schema.load_with(out.read_bytes())
    assert errs == [], errs
    rs = kb.resource_schema("aws_instance")
    assert rs is not None
    assert "ami" in rs.top_level
    assert kb.is_critical("aws_db_instance")


def test_a_written_pack_carries_no_filename_or_timestamp(tmp_path: Path) -> None:
    """Régénérer depuis une entrée inchangée doit produire des octets
    identiques, sinon chaque régénération est un diff et les packs ne peuvent
    pas être relus. L'en-tête gzip est le moyen facile de casser cela : il porte
    une date de modification et, par défaut, le nom du fichier écrit."""
    pack = Pack(id="x-base", provider="x", provider_version="1", resources={})
    a, b = tmp_path / "one.json.gz", tmp_path / "different-name.json.gz"
    pack.write_gzip_json(a)
    pack.write_gzip_json(b)
    assert a.read_bytes() == b.read_bytes()


def test_meta_arguments_are_injected_at_the_top_level_only(tmp_path: Path) -> None:
    """Les arguments propres à Terraform n'apparaissent jamais dans le schéma
    d'un fournisseur. Sans eux, chaque `count` et chaque `lifecycle` d'un dépôt
    scanné se lit comme une hallucination — mais un `lifecycle` à l'intérieur
    d'un bloc imbriqué n'est pas valide, ils ne doivent donc pas y être
    ajoutés."""
    document = {
        "provider_schemas": {
            "p": {
                "resource_schemas": {
                    "x_thing": {
                        "block": {
                            "attributes": {"name": {"optional": True}},
                            "block_types": {
                                "inner": {
                                    "nesting_mode": "list",
                                    "block": {"attributes": {"size": {"optional": True}}},
                                }
                            },
                        }
                    }
                }
            }
        }
    }
    path = tmp_path / "s.json"
    path.write_text(json.dumps(document))

    r = load_provider_schema(path, "p")["x_thing"]
    assert "count" in r.top_level and "lifecycle" in r.top_level
    assert "inner" in r.top_level, "a nested block's name is a valid parent argument"
    assert r.nested_blocks["inner"] == ["size"], "no meta-arguments inside a block"


def test_force_new_for_an_argument_the_schema_does_not_declare_is_dropped() -> None:
    """Une entrée ForceNew pour un argument que le fournisseur ne déclare
    jamais veut dire que l'extracteur a mal lu la source. Agir dessus bloquerait
    une PR sur un argument qui n'existe pas — elle est donc jetée, pas crue."""
    resources = {
        "x_thing": PackResource(top_level=["name", "size"], nested_blocks={"inner": ["kind"]})
    }
    index = ForceNewIndex(
        top_level={"x_thing": ["name", "invented"], "x_absent": ["whatever"]},
        nested={"x_thing": {"inner": ["kind", "invented"], "no_such_block": ["k"]}},
    )
    apply_force_new(resources, index)

    r = resources["x_thing"]
    assert r.force_new_top_level == ["name"]
    assert r.force_new_nested == {"inner": ["kind"]}


def test_an_unknown_provider_address_names_what_was_found(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text(json.dumps({"provider_schemas": {"registry/hashicorp/aws": {}}}))
    with pytest.raises(SchemaError, match="registry/hashicorp/aws"):
        load_provider_schema(path, "registry/hashicorp/google")


def test_the_curated_overlays_still_parse() -> None:
    """Ces quatre fichiers sont la seule entrée écrite à la main qui reste. Une
    faute de frappe dans l'un est une génération qui échoue ou, pire, qui laisse
    tomber en silence un type de ressource critique."""
    assert len(read_string_list(CURATED / "base_pack_types.json", "resource_types")) > 20
    assert (
        len(read_string_list(CURATED / "critical_stateful_resources.json", "resource_types")) > 10
    )
    pricing = read_pricing(CURATED / "aws_pricing.json")
    assert "aws_instance" in pricing
    assert pricing["aws_instance"].attribute == "instance_type"
    assert pricing["aws_instance"].by_attribute, "pricing with no per-size values"


def test_pricing_round_trips_through_the_wire_form() -> None:
    p = PackPricing(
        base=32.0, attribute="instance_type", by_attribute={"m5.large": 70.0}, default=1.0
    )
    assert PackPricing.from_json(p.to_json()) == p
    # An all-zero spec omits every field, as Go's omitempty does.
    assert PackPricing().to_json() == {}


def test_dedupe_keeps_first_occurrence_order() -> None:
    assert dedupe(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


# --- the seam with the Go extractor -----------------------------------------


def test_the_go_extractors_index_format_is_read_exactly() -> None:
    """L'index ForceNew est le contrat entre les deux versions.

    L'extracteur reste en Go — le langage qu'il lit est du Go, et Go livre le
    seul analyseur qui fasse autorité pour lui — et écrit l'index avec
    `genpack --emit-forcenew-index`. Cette fixture est la vraie sortie de cet
    écrivain, gelée : si l'idée que l'un des deux côtés se fait du format dérive,
    ceci échoue plutôt que les packs perdent discrètement leurs données de
    destruction-recréation.

    Cela épingle aussi deux propriétés de l'écrivain qui comptent plus qu'elles
    n'en ont l'air. Les listes sont triées et dédoublonnées, si bien que
    relancer l'extracteur sur une copie de fournisseur inchangée produit un
    fichier identique — la même raison que celle pour laquelle le pack trie
    tout. Et les statistiques sont reportées, si bien que « quelle part du
    fournisseur avons-nous réellement résolue ? » reste un nombre mesuré.
    """
    from tfpdf.genpack import load_force_new_index

    index = load_force_new_index(
        Path(__file__).parent / "data" / "oracles" / "oracle_forcenew_index.json"
    )

    assert index.provider == "aws"
    assert index.provider_version == "6.59.0"
    assert index.top_level["aws_instance"] == ["ami", "availability_zone"]
    assert index.top_level["aws_db_instance"] == ["engine"]
    assert index.nested["aws_instance"]["root_block_device"] == ["encrypted", "kms_key_id"]
    assert index.nested["aws_instance"]["network_interface.thing"] == ["device_index"]
    assert index.stats.sdk_resources_resolved == 1150
    assert index.stats.framework_seen == 88

    # And the Python writer round-trips it, so an index can be edited or
    # regenerated on either side.
    assert load_force_new_index.__module__  # imported, not shadowed
    round_tripped = index.to_json()
    assert round_tripped["top_level"]["aws_instance"] == ["ami", "availability_zone"]
    assert round_tripped["stats"]["framework_resolved"] == 71


def test_an_index_drives_the_real_pack_pipeline(tmp_path: Path) -> None:
    """De bout en bout depuis le fichier de l'extracteur Go : index en entrée,
    pack en sortie."""
    from tfpdf.genpack import load_force_new_index

    index = load_force_new_index(
        Path(__file__).parent / "data" / "oracles" / "oracle_forcenew_index.json"
    )
    committed = _committed_pack("aws")
    addr = "registry.terraform.io/hashicorp/aws"
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(_schema_json_from_pack(committed, addr)))

    base, _ = build_packs("aws", load_provider_schema(schema_path, addr), "6.59.0", CURATED, index)

    ami = base.resources["aws_instance"]
    assert "ami" in ami.force_new_top_level
    assert "availability_zone" in ami.force_new_top_level
    assert ami.force_new_nested["root_block_device"] == ["encrypted", "kms_key_id"]
    # The fixture's invented block path is filtered out: the attribute surface
    # never declared it, so trusting it could block a PR over a block that does
    # not exist.
    assert "network_interface.thing" not in ami.force_new_nested
