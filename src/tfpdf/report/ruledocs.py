"""Résout l'étiquette lisible d'une catégorie et sa documentation longue depuis
le pack de règles, et génère docs/rules.md.

Port de internal/report/ruledocs.go.

L'explication longue de chaque catégorie vit dans le pack de règles, pas ici.
C'était quatre cents lignes de Markdown dans des littéraux Go, donc améliorer
une phrase confuse demandait une chaîne d'outils Go et une release. C'est de la
prose : sa place est dans un fichier de données à côté de la règle.

`category_display` vit ici et non dans `markdown.py` comme en Go : c'est la même
question que `category_title`, et les séparer créerait un import circulaire.
"""

from __future__ import annotations

from dataclasses import dataclass

from .. import ruledef
from .finding import Category

#: The prefix a custom rule's category carries (see `tfpdf.customrules`).
CUSTOM_CATEGORY_PREFIX = "custom:"

#: Where the per-rule documentation lives. It points at the main branch rather
#: than a tag: a link inside a SARIF upload outlives the scanner version that
#: produced it, and a reader following it a year later wants the current
#: explanation, not an archived one.
DOCS_BASE_URL = "https://github.com/foadtalsi/tf-predeploy-firewall/blob/main/docs/rules.md"


@dataclass(slots=True, frozen=True)
class RuleHelp:
    """La documentation d'une catégorie, résolue depuis le pack."""

    full_description: str
    markdown: str


def lookup_rule_help(c: Category | str) -> RuleHelp | None:
    """La documentation d'une catégorie, ou None.

    Un pack qui échoue à se charger laisse les catégories sans documentation
    plutôt que d'arrêter le processus : ce module ne fait que rendre, et au
    moment où quoi que ce soit l'atteint, `tfpdf.rules` a déjà refusé de
    tourner sur un pack cassé. Les tests vérifient que chaque règle a une
    explication, si bien qu'une entrée réellement manquante est attrapée là
    plutôt que livrée.
    """
    try:
        pack = ruledef.builtin()
    except ruledef.RulePackError:
        return None
    d = pack.docs_for(str(c))
    if d is None:
        return None
    return RuleHelp(full_description=d.full_description, markdown=d.markdown)


def category_title(c: Category | str) -> str | None:
    """L'étiquette lisible d'une catégorie, depuis le pack.

    En garder une seconde copie dans le code ferait qu'une règle renommée se
    lirait d'une façon dans le commentaire de PR et d'une autre sur la page
    d'alerte vers laquelle il pointe.
    """
    try:
        pack = ruledef.builtin()
    except ruledef.RulePackError:
        return None
    d = pack.docs_for(str(c))
    if d is None or not d.title:
        return None
    return d.title


def category_display(c: Category | str) -> str:
    """Étiquette une catégorie pour le commentaire de PR.

    Les règles personnalisées — catégorie « custom:<id-de-règle> », venue de
    `tfpdf.customrules` — n'ont aucune entrée dans le pack intégré : elles sont
    rendues « Custom rule: <id> » au lieu de retomber sur une chaîne vide.
    """
    label = category_title(c)
    if label is not None:
        return label
    text = str(c)
    if text.startswith(CUSTOM_CATEGORY_PREFIX):
        return "Custom rule: " + text[len(CUSTOM_CATEGORY_PREFIX) :]
    return text


def rule_help_uri(c: Category | str) -> str:
    """Lien vers la section d'une catégorie dans la documentation publiée des
    règles."""
    return f"{DOCS_BASE_URL}#{c}"


_DOCS_PREAMBLE = """<!-- Generated from tfpdf/ruledef/rules.py. Do not edit by hand:
     edit the pack, then run "pytest --update-docs". -->

# Rules

Every finding this scanner produces belongs to one of the categories below.
Each says what it detects, why it is worth interrupting a merge for, and how
to disagree with it — a rule you can't turn off is a rule that gets the whole
tool turned off.

Suppression works at four levels, narrowest first:

| Scope | How |
|---|---|
| One line | `# tf-firewall-ignore: <category>` above or on the line |
| One path | `ignore_paths:` in `.github/tf-firewall.yml`, optionally scoped to categories |
| One category, everywhere | `ignore_rules:` in the same file |
| Everything that exists today | a committed baseline (`--write-baseline`) — keeps findings visible but non-blocking |

"""

_DOCS_EPILOGUE = (
    "Custom rules defined in your own config get the category `custom:<id>` "
    "and are documented by whatever `message:` you give them.\n"
)


def render_rule_docs() -> str:
    """Génère docs/rules.md depuis le pack de règles.

    Le fichier est généré plutôt qu'écrit à la main parce que `helpUri` y
    pointe depuis chaque envoi SARIF : une catégorie dont la section n'existe
    pas est un lien mort dans le tableau de bord de sécurité de quelqu'un, et le
    seul moyen d'être sûr que les deux s'accordent est que l'un produise
    l'autre. Un test régénère et compare.

    Les titres sont l'identifiant brut de la catégorie, pour que les ancres que
    construit `rule_help_uri` (#unknown_attribute) soient exactement celles que
    GitHub génère ; l'étiquette lisible passe en dessous.

    Le préambule nomme toujours la commande de régénération Go. C'est délibéré
    tant que les deux scanners coexistent : le fichier qu'il produit est comparé
    octet pour octet à celui de l'arbre Go, et reformuler l'instruction ferait
    diverger les deux sur une phrase plutôt que sur une règle.
    """
    # Deferred because Go has one package here and Python has five modules:
    # sarif imports this one for its help text, so importing it back at module
    # scope would close the circle. The catalogue is the SARIF rule array, so
    # it belongs there rather than being hoisted somewhere neutral.
    from .sarif import SARIF_RULES

    parts = [_DOCS_PREAMBLE]

    for r in SARIF_RULES:
        c = r.id
        h = lookup_rule_help(c)
        if h is None:
            continue
        # The help markdown is written to stand alone on a Code Scanning alert
        # page, where "##" is the top level. Nested under a category heading
        # here, it has to drop one level.
        body = ("\n" + h.markdown).replace("\n## ", "\n### ")
        parts.append(
            f"## {c}\n\n**{category_display(c)}**\n\n{h.full_description}\n{body}\n\n---\n\n"
        )

    parts.append(_DOCS_EPILOGUE)
    return "".join(parts)
