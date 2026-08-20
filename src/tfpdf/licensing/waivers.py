"""Dérogations par découverte, posées par un administrateur dans le tableau de
bord.

Port des types de internal/licensing/waivers.go.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class Waiver:
    """La décision d'un administrateur (Starter et plus, via le tableau de bord)
    d'accepter une découverte précise plutôt que de la laisser bloquer les
    fusions.

    Appariée par catégorie + ressource + fichier au sein d'un dépôt, et **non**
    par numéro de ligne : une ligne se décale quand du code sans rapport change
    au-dessus d'elle, et exiger une correspondance exacte de ligne ferait périmer
    une dérogation à la première modification étrangère.
    """

    category: str = ""
    resource: str = ""
    file_path: str = ""
    justification: str = ""


def waivers_from_json(doc: Any) -> list[Waiver]:
    """Décode la liste des dérogations.

    Une liste vide est la réponse normale pour un dépôt sur lequel personne
    n'a encore rien accordé.
    """
    if not isinstance(doc, list):
        return []
    out: list[Waiver] = []
    for raw in doc:
        if not isinstance(raw, dict):
            continue
        out.append(
            Waiver(
                category=str(raw.get("category", "")),
                resource=str(raw.get("resource", "")),
                file_path=str(raw.get("file", "")),
                justification=str(raw.get("justification", "")),
            )
        )
    return out
