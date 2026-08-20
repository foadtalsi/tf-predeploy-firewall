"""La politique d'organisation qu'un plan de contrôle Growth peut imposer.

Port des types de internal/licensing/policy.go.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class Policy:
    """Une surcharge des réglages par défaut du scanner, valable pour toute
    l'organisation, réservée au plan Growth et gérée centralement via le plan de
    contrôle plutôt qu'éparpillée dans le config.yml local de chaque dépôt.

    Un champ à `None` signifie « pas de surcharge pour ce réglage » : l'appelant
    garde ce que disait la configuration locale. C'est pourquoi chaque champ est
    optionnel plutôt que doté d'une valeur par défaut — Go utilise des pointeurs
    ici pour la même raison, et un `ignore_rules: []` que le plan de contrôle a
    délibérément envoyé n'est pas la même instruction qu'un `ignore_rules` dont
    il n'a jamais parlé.
    """

    block_threshold: str | None = None
    ignore_rules: list[str] | None = None
    plan_blast_radius_threshold: int | None = None
    cost_impact_threshold_usd: float | None = None

    #: A full custom-rules document (same format as the `custom_rules:` section
    #: of config/default.yml), managed centrally so an org does not have to
    #: commit rule changes to every repo separately. When set it **replaces**,
    #: rather than merges with, any custom_rules in the repo's local config —
    #: the same "central policy wins" precedent as `ignore_rules`.
    custom_rules_yaml: str | None = None

    #: Same meaning as the local config fields of the same name — requests
    #: review from these usernames/team slugs whenever a critical finding is
    #: present.
    require_second_reviewer_users: list[str] | None = None
    require_second_reviewer_teams: list[str] | None = None

    def is_empty(self) -> bool:
        """Dit si le plan de contrôle n'a envoyé aucune surcharge.

        Le plan de contrôle répond `{}` quand aucune politique n'existe, ce qui
        décode en une Policy dont tous les champs sont vides — et l'appelant
        veut `None` pour cela, pas un objet qui ne surcharge rien.
        """
        return all(
            getattr(self, f) is None
            for f in (
                "block_threshold",
                "ignore_rules",
                "plan_blast_radius_threshold",
                "cost_impact_threshold_usd",
                "custom_rules_yaml",
                "require_second_reviewer_users",
                "require_second_reviewer_teams",
            )
        )


def policy_from_json(document: Any) -> Policy:
    """Décode un document de politique, en traitant une clé absente comme
    « pas de surcharge »."""
    if not isinstance(document, dict):
        return Policy()

    def opt_str(key: str) -> str | None:
        v = document.get(key)
        return str(v) if v is not None else None

    def opt_list(key: str) -> list[str] | None:
        v = document.get(key)
        return [str(x) for x in v] if isinstance(v, list) else None

    return Policy(
        block_threshold=opt_str("block_threshold"),
        ignore_rules=opt_list("ignore_rules"),
        plan_blast_radius_threshold=(
            int(document["plan_blast_radius_threshold"])
            if document.get("plan_blast_radius_threshold") is not None
            else None
        ),
        cost_impact_threshold_usd=(
            float(document["cost_impact_threshold_usd"])
            if document.get("cost_impact_threshold_usd") is not None
            else None
        ),
        custom_rules_yaml=opt_str("custom_rules_yaml"),
        require_second_reviewer_users=opt_list("require_second_reviewer_users"),
        require_second_reviewer_teams=opt_list("require_second_reviewer_teams"),
    )
