"""Le commentaire de pull request.

Port de internal/report/markdown.go.
"""

from __future__ import annotations

from .finding import Finding, Severity
from .ruledocs import category_display

#: Délimite le commentaire de l'outil pour que les exécutions suivantes le
#: retrouvent et le modifient, au lieu d'en poster un nouveau à chaque push.
MARKER = "<!-- tf-predeploy-firewall:report -->"

SEVERITY_EMOJI = {
    Severity.LOW: "🔵",
    Severity.MEDIUM: "🟡",
    Severity.HIGH: "🟠",
    Severity.CRITICAL: "🔴",
}


def _by_file_then_line(finding: Finding) -> tuple[str, int, str, str]:
    """Un ordre **total**, contrairement à celui de Go.

    Go trie sur `(fichier, ligne)` seuls avec `sort.Slice`, qui n'est pas
    stable : l'ordre relatif de deux découvertes sur la même ligne est donc
    décidé par la permutation que le pdqsort de Go produit. Elle est
    reproductible pour une entrée donnée et arbitraire à tout autre égard, et
    elle peut changer lors d'une montée de version de Go — un commentaire de PR
    se réordonnerait en silence sans qu'aucune règle ait bougé. Deux découvertes
    sur une même ligne n'a rien d'exotique non plus : une ressource avec état et
    un mot de passe en dur reçoit `missing_lifecycle` et `tutorial_pattern` sur
    sa ligne d'en-tête.

    Étendre la clé à la catégorie et au message spécifie l'ordre au lieu d'en
    hériter.

    Cela ne reproduit **pas** la sortie de Go octet pour octet. Sur le corpus
    de fixtures, `tutorial_pattern.tf` ligne 1 porte deux découvertes —
    `missing_lifecycle` et `tutorial_pattern` — et les deux implémentations les
    émettent dans un ordre différent. C'est le comportement voulu : notre ordre
    est spécifié, celui de Go est celui que son pdqsort a produit ce jour-là.
    Les tests de parité comparent donc les lignes du Markdown comme un
    multiensemble plus la séquence (fichier, ligne), et non octet pour octet ;
    SARIF et Code Quality, eux, restent identiques au bit près. La correction a
    sa place côté Go également, où le comparateur devrait porter les deux mêmes
    champs.
    """
    return (finding.file, finding.line, str(finding.category), finding.message)


def render_markdown(findings: list[Finding], threshold: Severity | str, blocked: bool) -> str:
    """Construit le corps complet du commentaire de PR pour un ensemble de
    découvertes.

    `blocked` indique si le seuil de sévérité configuré a été franchi par les
    découvertes ACTIVES, c'est-à-dire non couvertes par une dérogation. Une
    découverte avec dérogation ne contribue jamais à `blocked`, mais apparaît
    quand même dans sa propre section plus bas : en accepter une n'est jamais
    silencieux.
    """
    sections: list[str] = [MARKER + "\n", "## TF Pre-Deploy Firewall\n\n"]

    active = [finding for finding in findings if not finding.waived]
    waived = [finding for finding in findings if finding.waived]

    if not active and not waived:
        sections.append("No risk patterns detected in the changed Terraform files. ✅\n")
        return "".join(sections)

    # Clé totale, contrairement au sort.Slice de Go : deux découvertes sur le
    # même fichier et la même ligne sont départagées par la catégorie puis le
    # message, et non par une permutation arbitraire. Voir _by_file_then_line.
    active.sort(key=_by_file_then_line)

    if not active:
        sections.append(
            f"✅ No blocking findings — {len(waived)} finding(s) previously "
            "accepted (see below).\n\n"
        )
    elif blocked:
        sections.append(
            f"🚫 **Merge blocked** — findings at or above `{highest_severity(active)}` "
            f"severity (threshold: `{threshold}`).\n\n"
        )
    else:
        sections.append(
            f"⚠️ {len(active)} finding(s), none reach the `{threshold}` blocking threshold.\n\n"
        )

    if active:
        sections.append("| Severity | File | Line | Category | Resource | Detail |\n")
        sections.append("|---|---|---|---|---|---|\n")
        for finding in active:
            sections.append(
                f"| {SEVERITY_EMOJI.get(finding.severity, '')} {finding.severity} | `{finding.file}` | "
                f"{finding.line} | {category_display(finding.category)} | {resource_cell(finding)} | "
                f"{finding.message} |\n"
            )

    _render_suggestions(sections, active)
    _render_waivers(sections, waived)

    return "".join(sections)


def _render_waivers(sections: list[str], waived: list[Finding]) -> None:
    """Liste les découvertes qu'un administrateur a acceptées via le plan de
    contrôle (Starter et plus, GET /v1/waivers).

    Elles restent visibles pour qu'une dérogation soit une décision documentée
    et non une disparition silencieuse du rapport.
    """
    if not waived:
        return
    waived = sorted(waived, key=_by_file_then_line)

    sections.append(
        f"\n<details><summary>{len(waived)} accepted finding(s) — excluded from "
        "the block decision</summary>\n\n"
    )
    sections.append(
        "| Severity | File | Line | Category | Resource | Detail | Accepted because |\n"
    )
    sections.append("|---|---|---|---|---|---|---|\n")
    for finding in waived:
        sections.append(
            f"| {SEVERITY_EMOJI.get(finding.severity, '')} {finding.severity} | `{finding.file}` | "
            f"{finding.line} | {category_display(finding.category)} | {resource_cell(finding)} | "
            f"{finding.message} | {finding.waiver_note} |\n"
        )
    sections.append("\n</details>\n")


def resource_cell(f: Finding) -> str:
    """Rend l'adresse de la ressource, liée à la documentation du fournisseur
    pour son type quand elle est connue.

    Le lien est porté par l'adresse plutôt que par une colonne à lui : une
    septième colonne coûterait de la largeur à chaque ligne, sur un tableau déjà
    large, pour porter le même mot partout.
    """
    if not f.doc_url:
        return "`" + f.resource + "`"
    return f"[`{f.resource}`]({f.doc_url})"


def _render_suggestions(sections: list[str], sorted_findings: list[Finding]) -> None:
    """Ajoute un bloc repliable « Suggested fixes » par découverte qui en a un.

    C'est du HCL à copier-coller, pas un patch calculé : cet outil n'a jamais
    d'accès en écriture au dépôt. Gardé hors du tableau principal, un bloc de
    code multi-lignes ne tenant pas dans une cellule de tableau markdown.
    """
    if not any(finding.suggestion for finding in sorted_findings):
        return

    sections.append("\n### Suggested fixes\n\n")
    for finding in sorted_findings:
        if not finding.suggestion:
            continue
        sections.append(
            f"<details><summary><code>{finding.resource}</code> ({finding.file}:{finding.line})</summary>"
            f"\n\n```hcl\n{finding.suggestion}\n```\n\n</details>\n\n"
        )


def highest_severity(findings: list[Finding]) -> Severity:
    highest = Severity.LOW
    for finding in findings:
        if finding.severity.at_least(highest):
            highest = finding.severity
    return highest
