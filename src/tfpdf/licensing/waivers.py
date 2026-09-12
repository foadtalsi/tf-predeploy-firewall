"""Finding-specific waivers granted by an administrator in the hosted dashboard."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True, frozen=True)
class Waiver:
    """An administrator's decision to accept a finding instead of blocking merges, available on
    Starter and above.
    """

    category: str = ""
    resource: str = ""
    file_path: str = ""
    justification: str = ""


def waivers_from_json(document: Any) -> list[Waiver]:
    """Decode waivers; an empty list is normal when none have been granted."""
    if not isinstance(document, list):
        return []
    out: list[Waiver] = []
    for raw in document:
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
