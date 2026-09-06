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

La correspondance se fait sur règle + catégorie + ressource + fichier, **pas**
sur le numéro de ligne : une référence qui casse dès qu'on ajoute une ligne
au-dessus serait pire que pas de référence.

`rule_name` fait partie de la clé depuis la version 2 du format, et son absence
était un vrai trou. Plusieurs règles partagent une catégorie : « prevent_destroy
manquant » et « force_destroy sur un compartiment » sont toutes deux
`missing_lifecycle`. Sur la même ressource et le même fichier, elles avaient donc
la même clé — accepter la première acceptait la seconde, en silence.

Ce n'est pas théorique. Sur notre propre infrastructure, la lecture cloud avait
fait monter `force_destroy` de medium à **critical** en constatant que les deux
compartiments existaient et n'étaient pas vides ; la découverte est arrivée dans
le rapport déjà neutralisée par une entrée écrite pour le prevent_destroy
manquant. Toute la valeur de la vérification était annulée par une dérogation
accordée pour autre chose.
"""

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
        """Marque comme acceptée toute découverte présente dans la référence.

        Réutilise le même mécanisme « accepté mais toujours affiché » que les
        dérogations : une découverte de la référence est exclue de la décision de
        blocage et du SARIF, mais ne disparaît jamais silencieusement du rapport.

        Deux appariements, et un seul s'applique à un fichier donné.

        **Version 2, exact.** Le nom de la règle fait partie de la clé. Accepter
        « prevent_destroy manquant » sur un compartiment n'accepte plus
        « force_destroy » sur le même compartiment.

        **Version 1, permissif.** Ces entrées n'ont pas de nom de règle, et
        aucune reconstruction n'est possible : le fichier ne dit pas laquelle
        des règles d'une catégorie son auteur avait acceptée. Elles apparient
        donc comme avant, c'est-à-dire trop largement. C'est délibéré : le seul
        autre choix serait de ne plus les apparier du tout, ce qui rendrait
        bloquantes des centaines de découvertes déjà acceptées, dans chaque
        dépôt, à la première exécution après la mise à jour. Le trou reste ouvert
        jusqu'à un `--write-baseline`, et `legacy` est là pour qu'on le dise.
        """
        for f in findings:
            entry = Entry(
                category=str(f.category),
                resource=f.resource,
                file=f.file,
                rule_name=f.rule_name,
            )
            exact = entry.key()
            if exact in self.by_key:
                matched = exact
            elif (loose := entry.legacy_key()) in self.by_legacy_key:
                matched = loose
            else:
                continue
            self.used.add(matched)
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
            rule_name=f.rule_name,
            message=f.message,
            line=f.line,
        )
        if e.key() in seen:
            continue
        seen.add(e.key())
        entries.append(e)

    # Stable order so regenerating an unchanged repo produces no diff.
    entries.sort(key=lambda e: (e.file, e.resource, e.category, e.rule_name))

    document = {
        "format_version": FORMAT_VERSION,
        "generated_at": generated_at,
        "_note": _NOTE,
        "entries": [
            {
                "category": e.category,
                "resource": e.resource,
                "file": e.file,
                # Écrit même vide, contrairement à message et line : son absence
                # est ce qui distinguait un fichier de version 1, et un lecteur
                # qui ne le verrait pas sur une entrée de version 2 croirait à un
                # fichier tronqué.
                "rule_name": e.rule_name,
                **({"message": e.message} if e.message else {}),
                **({"line": e.line} if e.line else {}),
            }
            for e in entries
        ],
    }
    Path(path).write_text(json.dumps(document, indent=2) + "\n")
