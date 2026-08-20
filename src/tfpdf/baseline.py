"""Consigne les découvertes déjà présentes dans un dépôt pour qu'elles ne
bloquent pas la fusion, tout en bloquant les nouvelles.

Port de internal/baseline/baseline.go.

Sans cela, pointer le scanner sur un parc Terraform mature rapporte des
centaines de découvertes défendables et collectivement inutiles : la seule
réponse disponible serait d'abaisser `block_threshold` jusqu'au silence, ce qui
revient à désinstaller l'outil.

Une référence est un fichier versionné. Les découvertes qu'elle contient
apparaissent toujours dans le commentaire de PR, dans leur propre section, sans
bloquer. Toute nouveauté bloque.

La correspondance se fait sur catégorie + ressource + fichier, **pas** sur le
numéro de ligne : une référence qui casse dès qu'on ajoute une ligne au-dessus
serait pire que pas de référence. Même clé que les dérogations du plan de
contrôle, pour qu'« accepté » veuille dire une seule chose.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .report.finding import Finding

#: Guards against reading a baseline written by a future scanner whose
#: semantics we don't know. Accepting one blindly could silence findings the
#: author never agreed to.
FORMAT_VERSION = 1

_NOTE = (
    "Findings accepted as pre-existing. They stay visible in the PR comment but do not "
    "block a merge; anything not listed here does. Matched on category+resource+file, "
    "never on line number. Regenerate with --write-baseline."
)


@dataclass(slots=True, frozen=True)
class Entry:
    """Une découverte acceptée."""

    category: str
    resource: str
    file: str

    #: Recorded for the human reading the diff of this file — never matched on.
    #: Messages get reworded as the scanner improves, and lines move; matching
    #: on either would make every upgrade resurrect the whole backlog.
    message: str = ""
    line: int = 0

    def key(self) -> str:
        return f"{self.category}\x00{self.resource}\x00{self.file}"


@dataclass(slots=True)
class Baseline:
    """Une référence chargée, prête à être confrontée aux découvertes."""

    by_key: dict[str, Entry] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Marque comme acceptée toute découverte présente dans la référence.

        Réutilise le même mécanisme « accepté mais toujours affiché » que les
        dérogations : une découverte de la référence est exclue de la décision de
        blocage et du SARIF, mais ne disparaît jamais silencieusement du rapport.
        """
        for f in findings:
            k = Entry(category=str(f.category), resource=f.resource, file=f.file).key()
            if k not in self.by_key:
                continue
            self.used.add(k)
            f.waived = True
            f.waiver_note = "accepted in baseline"
        return findings

    def stale(self) -> int:
        """Combien d'entrées de la référence n'ont rien trouvé dans ce scan —
        découvertes depuis corrigées, ou ressources supprimées.

        Rapporté plutôt qu'élagué automatiquement : retirer des entrées en silence
        laisserait une référence ré-accepter discrètement une découverte qui
        reviendrait plus tard. Le nettoyage est un `--write-baseline` délibéré.
        """
        return len(self.by_key) - len(self.used)

    def size(self) -> int:
        """Combien de découvertes la référence accepte."""
        return len(self.by_key)


def load(path: str) -> Baseline | None:
    """Lit un fichier de référence.

    Un fichier absent n'est pas une erreur : cela veut dire « pas de
    référence », l'état normal de la plupart des dépôts.
    """
    if not path:
        return None
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError(f"reading baseline {path}: {exc}") from exc

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parsing baseline {path}: {exc}") from exc
    if not isinstance(doc, dict):
        raise ValueError(f"parsing baseline {path}: top level is not an object")

    version = int(doc.get("format_version", 0) or 0)
    if version != FORMAT_VERSION:
        raise ValueError(
            f"baseline {path} has format version {version}, this scanner understands "
            f"{FORMAT_VERSION} — regenerate it with --write-baseline"
        )

    b = Baseline()
    for e in doc.get("entries") or []:
        entry = Entry(
            category=str(e.get("category", "")),
            resource=str(e.get("resource", "")),
            file=str(e.get("file", "")),
            message=str(e.get("message", "")),
            line=int(e.get("line", 0) or 0),
        )
        b.by_key[entry.key()] = entry
    return b


def write(path: str, findings: list[Finding], generated_at: str) -> None:
    """Consigne les découvertes données comme nouvelle référence.

    Seules des découvertes réellement rapportables doivent être passées ici :
    écrire une référence à partir d'un scan sur lequel des dérogations ont été
    appliquées graverait ces dérogations dans le fichier et les rendrait
    permanentes, leur faisant survivre à la décision du tableau de bord qui les
    a créées.
    """
    seen: set[str] = set()
    entries: list[Entry] = []

    for f in findings:
        e = Entry(
            category=str(f.category),
            resource=f.resource,
            file=f.file,
            message=f.message,
            line=f.line,
        )
        if e.key() in seen:
            continue
        seen.add(e.key())
        entries.append(e)

    # Stable order so regenerating an unchanged repo produces no diff.
    entries.sort(key=lambda e: (e.file, e.resource, e.category))

    doc = {
        "format_version": FORMAT_VERSION,
        "generated_at": generated_at,
        "_note": _NOTE,
        "entries": [
            {
                "category": e.category,
                "resource": e.resource,
                "file": e.file,
                **({"message": e.message} if e.message else {}),
                **({"line": e.line} if e.line else {}),
            }
            for e in entries
        ],
    }
    Path(path).write_text(json.dumps(doc, indent=2) + "\n")
