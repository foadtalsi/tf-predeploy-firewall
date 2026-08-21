"""Superposition d'un pack de règles sur un autre.

Port de internal/ruledef/merge.go.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .ruledef import CategoryDoc, Pack, Rule, RulePackError

_MAX_LISTED = 5


@dataclass(slots=True)
class MergeReport:
    """Ce que la superposition d'un pack sur un autre a réellement fait.

    Existe pour être affiché. Un pack qui surcharge une règle que l'auteur ne
    voulait pas surcharger, ou qui en ajoute une dont il a mal tapé
    l'identifiant au point d'en créer une nouvelle, se comporte parfaitement et
    silencieusement — le scan exécute simplement des règles différentes de ce
    qu'il croit. Les décomptes sont bon marché à lire sur stderr et rendent cela
    visible.
    """

    overridden: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    disabled: list[str] = field(default_factory=list)
    inherited: int = 0

    def __str__(self) -> str:
        s = f"{self.inherited} inherited"
        if self.overridden:
            s += f", {len(self.overridden)} overridden ({_join(self.overridden)})"
        if self.added:
            s += f", {len(self.added)} added ({_join(self.added)})"
        if self.disabled:
            s += f", {len(self.disabled)} disabled ({_join(self.disabled)})"
        return s


def _join(ids: list[str]) -> str:
    if len(ids) <= _MAX_LISTED:
        return ", ".join(ids)
    return ", ".join(ids[:_MAX_LISTED]) + f" and {len(ids) - _MAX_LISTED} more"


def merge(base: Pack | None, overlay: Pack | None) -> tuple[Pack, MergeReport]:
    """Superpose `overlay` sur `base` et rend le pack combiné.

    Les règles sont appariées par identifiant. Une règle de la surcouche dont
    l'identifiant existe dans la base la remplace *à la position de la base*, si
    bien que surcharger une règle ne peut pas réordonner les autres — et l'ordre
    porte du sens ici, puisque les membres d'un groupe sont des alternatives
    ordonnées. Une règle de surcouche portant un identifiant neuf est ajoutée à
    la fin.

    Aucune des deux entrées n'est modifiée : le pack intégré est un singleton à
    l'échelle du processus, et une fusion qui le muterait laisserait tous les
    appelants suivants regarder la surcouche de quelqu'un d'autre.
    """
    if base is None or overlay is None:
        raise RulePackError("both packs are required")

    report = MergeReport()

    by_id: dict[str, Rule] = {}
    for r in overlay.rules:
        if r.id in by_id:
            raise RulePackError(f"overlay declares id {r.id!r} twice")
        by_id[r.id] = r

    merged_rules: list[Rule] = []
    merged_docs: list[CategoryDoc] = []
    used: set[str] = set()

    for r in base.rules:
        override = by_id.get(r.id)
        if override is not None:
            used.add(r.id)
            if override.disabled:
                report.disabled.append(r.id)
                continue
            report.overridden.append(r.id)
            merged_rules.append(override)
            continue
        report.inherited += 1
        merged_rules.append(r)

    for r in overlay.rules:
        if r.id in used:
            continue
        if r.disabled:
            # Disabling something that was never there is the signature of a
            # typo, and a typo here means the rule the author meant to switch
            # off is still running.
            raise RulePackError(
                f"rule {r.id!r} is marked disabled but no rule with that id exists to "
                "disable — check the spelling against --print-rules"
            )
        report.added.append(r.id)
        merged_rules.append(r)

    # Docs merge by category on the same override-or-append terms, so a pack
    # that reworded a rule can reword its explanation too. A rule whose
    # documentation still describes the old behaviour is worse than none.
    doc_by_cat = {d.category: d for d in overlay.docs}
    used_doc: set[str] = set()
    for d in base.docs:
        override_doc = doc_by_cat.get(d.category)
        if override_doc is not None:
            used_doc.add(d.category)
            merged_docs.append(override_doc)
            continue
        merged_docs.append(d)
    for d in overlay.docs:
        if d.category not in used_doc:
            merged_docs.append(d)

    if not merged_rules:
        raise RulePackError("the merged pack has no rules left — the overlay disabled every one")

    merged = Pack(version=base.version, rules=merged_rules, docs=merged_docs)

    # Revalidated from scratch rather than trusted: two individually valid
    # packs can merge into an invalid one, most obviously by overriding a group
    # member with a rule of a different scope.
    try:
        merged.index()
    except RulePackError as exc:
        raise RulePackError(f"merging packs: {exc}") from exc

    report.overridden.sort()
    report.added.sort()
    report.disabled.sort()
    return merged, report
