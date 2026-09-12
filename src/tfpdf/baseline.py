"""Consigne les découvertes déjà présentes dans un dépôt pour qu'elles ne bloquent pas la fusion,
tout en bloquant les nouvelles."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .report.finding import Finding

#: Guards against reading a baseline written by a future scanner whose
#: semantics we don't know. Accepting one blindly could silence findings the
#: author never agreed to.
FORMAT_VERSION = 2

#: Les versions qu'on sait lire. La 1 n'a pas de `rule_name` dans ses entrées et
#: est appariée de façon PERMISSIVE — voir `Baseline.apply`. Elle reste acceptée
#: parce que la refuser ferait passer au rouge, du jour au lendemain, la CI de
#: tout dépôt portant une référence existante, sur du code que personne n'a
#: touché. Une montée de version qui punit ceux qui ont adopté l'outil tôt est
#: une montée de version que personne n'applique.
READABLE_VERSIONS = frozenset({1, 2})

#: Ce que la version 1 ne pouvait pas dire.
LEGACY_VERSION = 1

_NOTE = (
    "Findings accepted as pre-existing. They stay visible in the PR comment but do not "
    "block a merge; anything not listed here does. Matched on rule+category+resource+file, "
    "never on line number. Regenerate with --write-baseline."
)


@dataclass(slots=True, frozen=True)
class Entry:
    """Une découverte acceptée."""

    category: str
    resource: str
    file: str

    #: L'identifiant de la règle. Vide pour une entrée venue d'une référence en
    #: version 1, qui ne le portait pas — et vide aussi, légitimement, pour la
    #: seule découverte que le scanner produit sans règle (un fichier qu'il n'a
    #: pas su analyser). Ces deux « vides » ne veulent pas dire la même chose,
    #: et c'est la VERSION DU FICHIER qui les sépare, jamais le champ : une
    #: entrée de version 2 sans nom de règle est une entrée exacte dont le nom
    #: est vide, pas une entrée floue.
    rule_name: str = ""

    #: Recorded for the human reading the diff of this file — never matched on.
    #: Messages get reworded as the scanner improves, and lines move; matching
    #: on either would make every upgrade resurrect the whole backlog.
    message: str = ""
    line: int = 0

    def key(self) -> str:
        """La clé exacte, celle de la version 2."""
        return f"{self.category}\x00{self.resource}\x00{self.file}\x00{self.rule_name}"

    def legacy_key(self) -> str:
        """La clé de la version 1, sans nom de règle.

        Ne peut pas entrer en collision avec `key()` : celle-ci porte toujours
        un quatrième séparateur, même quand le nom de règle est vide.
        """
        return f"{self.category}\x00{self.resource}\x00{self.file}"


@dataclass(slots=True)
class Baseline:
    """Une référence chargée, prête à être confrontée aux découvertes."""

    #: Entrées de version 2, appariées exactement (nom de règle compris).
    by_key: dict[str, Entry] = field(default_factory=dict)
    #: Entrées de version 1, appariées sans nom de règle.
    by_legacy_key: dict[str, Entry] = field(default_factory=dict)
    used: set[str] = field(default_factory=set)
    #: Vrai quand le fichier lu était en version 1. L'appelant s'en sert pour
    #: dire à l'utilisateur ce qu'il perd, ce que ce module ne peut pas faire
    #: lui-même — il n'imprime rien.
    legacy: bool = False

    def apply(self, findings: list[Finding]) -> list[Finding]:
        """Marque les découvertes présentes dans la référence comme acceptées, sans les supprimer
        du rapport."""
        for finding in findings:
            entry = Entry(
                category=str(finding.category),
                resource=finding.resource,
                file=finding.file,
                rule_name=finding.rule_name,
            )
            exact = entry.key()
            if exact in self.by_key:
                matched = exact
            elif (loose := entry.legacy_key()) in self.by_legacy_key:
                matched = loose
            else:
                continue
            self.used.add(matched)
            finding.waived = True
            finding.waiver_note = "accepted in baseline"
        return findings

    def stale(self) -> int:
        """Combien d'entrées de la référence n'ont rien trouvé dans ce scan — découvertes depuis
        corrigées, ou ressources supprimées."""
        return self.size() - len(self.used)

    def size(self) -> int:
        """Combien de découvertes la référence accepte."""
        return len(self.by_key) + len(self.by_legacy_key)


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
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"parsing baseline {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"parsing baseline {path}: top level is not an object")

    version = int(document.get("format_version", 0) or 0)
    if version not in READABLE_VERSIONS:
        readable = ", ".join(str(v) for v in sorted(READABLE_VERSIONS))
        raise ValueError(
            f"baseline {path} has format version {version}, this scanner understands "
            f"{readable} — regenerate it with --write-baseline"
        )

    legacy = version == LEGACY_VERSION
    b = Baseline(legacy=legacy)
    for e in document.get("entries") or []:
        entry = Entry(
            category=str(e.get("category", "")),
            resource=str(e.get("resource", "")),
            file=str(e.get("file", "")),
            # Lu même en version 1 : rien n'interdit à quelqu'un d'avoir ajouté
            # le champ à la main, et le garder rend le fichier lisible. Il ne
            # change PAS la façon dont l'entrée est appariée — c'est la version
            # du fichier qui en décide, et elle seule.
            rule_name=str(e.get("rule_name", "")),
            message=str(e.get("message", "")),
            line=int(e.get("line", 0) or 0),
        )
        if legacy:
            b.by_legacy_key[entry.legacy_key()] = entry
        else:
            b.by_key[entry.key()] = entry
    return b


def write(path: str, findings: list[Finding], generated_at: str) -> None:
    """Écrit les découvertes de référence de façon atomique, avec permissions restreintes et sans
    messages pouvant contenir des secrets."""
    seen: set[str] = set()
    entries: list[Entry] = []

    for finding in findings:
        entry = Entry(
            category=str(finding.category),
            resource=finding.resource,
            file=finding.file,
            rule_name=finding.rule_name,
            message=finding.message,
            line=finding.line,
        )
        if entry.key() in seen:
            continue
        seen.add(entry.key())
        entries.append(entry)

    # Stable order so regenerating an unchanged repo produces no diff.
    entries.sort(key=lambda entry: (entry.file, entry.resource, entry.category, entry.rule_name))

    document = {
        "format_version": FORMAT_VERSION,
        "generated_at": generated_at,
        "_note": _NOTE,
        "entries": [
            {
                "category": entry.category,
                "resource": entry.resource,
                "file": entry.file,
                # Écrit même vide, contrairement à message et line : son absence
                # est ce qui distinguait un fichier de version 1, et un lecteur
                # qui ne le verrait pas sur une entrée de version 2 croirait à un
                # fichier tronqué.
                "rule_name": entry.rule_name,
                **({"message": entry.message} if entry.message else {}),
                **({"line": entry.line} if entry.line else {}),
            }
            for entry in entries
        ],
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n")
