"""Analyse du JSON produit par `terraform show -json <planfile>` — l'entrée de
la phase 2.

Port de internal/planjson/model.go.

Contrairement au scan statique de la phase 1, ceci exige que le job CI de
l'utilisateur exécute lui-même `terraform plan` avec de vrais identifiants
cloud ; cet outil ne lance jamais terraform lui-même. Il ne
fait que lire le JSON résultant, pour détecter des risques qu'un diff HCL pur ne
peut pas voir : une destruction ou un remplacement confirmé, un plan touchant
bien plus de ressources que le diff de la PR elle-même, ou un attribut sensible
qui dérive hors des changements de la PR.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Change:
    """L'objet `change` d'une entrée.

    `before` et `after` sont décodés en dictionnaires génériques (les nombres
    JSON deviennent des flottants) — suffisant pour des tests d'égalité, ce dont
    les règles se contentent. `before_sensitive` et `after_sensitive` reflètent
    les marques de sensibilité de Terraform : pour un attribut sensible, le
    masque contient `true` (ou un map ou tableau imbriqué de masques pour les
    valeurs structurées), **alors même que before et after contiennent toujours
    la vraie valeur en clair**. Tout appelant qui affiche une valeur d'attribut
    dans un message de découverte DOIT consulter ces masques d'abord et
    caviarder, puisque les découvertes finissent dans des commentaires de PR et
    des sorties SARIF susceptibles d'être vues par un public plus large que le
    plan lui-même.
    """

    actions: list[str] = field(default_factory=list)

    #: `None` when the plan says `null`, which is not the same as an empty
    #: object: a create has no before-state at all. Go models these as nilable
    #: maps and the cost rule branches on `state == nil` to charge $0 for the
    #: side that does not exist — collapsing both to `{}` would price a
    #: newly-created flat-rate resource at its base cost on *both* sides and
    #: report a delta of zero.
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    before_sensitive: dict[str, Any] | None = None
    after_sensitive: dict[str, Any] | None = None

    def is_sensitive_attr(self, attr_name: str) -> bool:
        """Dit si `attr_name` est marqué sensible dans l'un ou l'autre état."""
        return _is_masked_true(self.before_sensitive, attr_name) or _is_masked_true(
            self.after_sensitive, attr_name
        )

    def is_replace(self) -> bool:
        """Dit si ce changement détruit puis recrée la ressource.

        Les actions contiennent à la fois « delete » et « create », dans un
        ordre ou dans l'autre : Terraform émet ["delete","create"] pour un
        remplacement, contre ["create","delete"] pour un remplacement
        create-before-destroy.
        """
        return "delete" in self.actions and "create" in self.actions

    def is_destroy_only(self) -> bool:
        """Dit si la ressource est supprimée sans remplacement — l'action la plus
        dangereuse qu'un plan puisse contenir."""
        return self.actions == ["delete"]

    def is_pure_update(self) -> bool:
        """Dit si le changement est une mise à jour sur place, sans destruction ni
        recréation."""
        return self.actions == ["update"]

    def is_no_op(self) -> bool:
        """Dit si Terraform n'a rien trouvé à faire pour cette ressource."""
        return self.actions == ["no-op"]


def _is_masked_true(mask: dict[str, Any] | None, attr_name: str) -> bool:
    if not mask:
        return False
    return mask.get(attr_name) is True


@dataclass(slots=True)
class ResourceChange:
    """Une entrée de `resource_changes[]`."""

    address: str = ""
    module_addr: str = ""
    #: "managed" (a real resource) or "data" (a data source read).
    mode: str = ""
    type: str = ""
    name: str = ""
    provider_name: str = ""
    change: Change = field(default_factory=Change)

    def is_managed(self) -> bool:
        """Dit si cette entrée est une vraie ressource gérée par Terraform, par
        opposition à la lecture d'une source de données.

        Les règles doivent sauter les sources de données : elles ne sont jamais
        détruites, remplacées ni dérivées au sens qui intéresse ces règles, et
        une source de données peut partager un nom de type avec une ressource
        gérée sans rapport.
        """
        return self.mode == "managed"


@dataclass(slots=True)
class PlanFile:
    """Le sous-ensemble minimal du schéma de `terraform show -json`
    (format_version 1.x) que cet outil comprend."""

    format_version: str = ""
    resource_changes: list[ResourceChange] = field(default_factory=list)


def _as_dict(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _as_dict_or_none(v: Any) -> dict[str, Any] | None:
    """Préserve un `null` JSON comme une absence, comme le fait le map nilable
    de Go.

    Décoder les deux en dictionnaire vide — le réflexe Python — ferait chercher
    l'attribut de tarification dans un dictionnaire vide des deux côtés, et
    calculer un delta nul : un plan créant une passerelle NAT ne rapporterait
    aucun impact de coût.
    """
    return v if isinstance(v, dict) else None


def parse(data: bytes | str) -> PlanFile:
    """Décode un document JSON de plan."""
    try:
        document = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parsing plan JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("parsing plan JSON: top level is not an object")

    changes: list[ResourceChange] = []
    for rc in document.get("resource_changes") or []:
        if not isinstance(rc, dict):
            continue
        c = _as_dict(rc.get("change"))
        changes.append(
            ResourceChange(
                address=str(rc.get("address", "")),
                module_addr=str(rc.get("module_address", "")),
                mode=str(rc.get("mode", "")),
                type=str(rc.get("type", "")),
                name=str(rc.get("name", "")),
                provider_name=str(rc.get("provider_name", "")),
                change=Change(
                    actions=[str(a) for a in (c.get("actions") or [])],
                    before=_as_dict_or_none(c.get("before")),
                    after=_as_dict_or_none(c.get("after")),
                    before_sensitive=_as_dict_or_none(c.get("before_sensitive")),
                    after_sensitive=_as_dict_or_none(c.get("after_sensitive")),
                ),
            )
        )

    return PlanFile(
        format_version=str(document.get("format_version", "")), resource_changes=changes
    )


def load(path: str) -> PlanFile:
    """Lit et décode un fichier JSON de plan."""
    try:
        return parse(Path(path).read_bytes())
    except OSError as exc:
        raise ValueError(f"reading plan JSON {path}: {exc}") from exc
