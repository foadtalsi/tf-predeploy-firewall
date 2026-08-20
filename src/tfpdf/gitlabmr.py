"""Publication des résultats de scan sur une merge request GitLab.

Port de internal/gitlabmr/gitlabmr.go.

Même forme que `githubpr`, grammaire différente en dessous. Les trois
différences qui comptent :

  * Un commentaire en ligne a besoin d'un objet de position portant les SHA de
    diff exacts de la MR (base, start, head), récupérés depuis la MR elle-même
    — et pas seulement d'un chemin et d'une ligne.
  * Le bloc de suggestion est relatif à une plage : ```suggestion:-0+2 remplace
    la ligne commentée plus les deux suivantes, là où le ```suggestion simple
    de GitHub remplace la plage ancrée du commentaire. Le rendu a lieu dans
    `report`, qui connaît les deux grammaires.
  * Chaque discussion est son propre POST ; il n'y a pas d'objet « revue »
    groupé, donc un échec partiel laisse les commentaires précédents postés.
    Les marqueurs rendent la reprise idempotente.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

from ._httpjson import HTTPError, get_json, send_json
from .forge import InlineComment, SuggestionOutcome, lines_in_diff, patch_line_numbers

_MAX_PAGES = 10


class GitLabConfigError(RuntimeError):
    """L'environnement ne décrit aucune merge request où publier."""


@dataclass(slots=True)
class DiffRefs:
    base: str = ""
    start: str = ""
    head: str = ""


@dataclass(slots=True)
class Client:
    """Dialogue avec une merge request."""

    #: GitLab's v4 API root, e.g. https://gitlab.com/api/v4 — CI provides it
    #: as CI_API_V4_URL, which also makes self-hosted instances work
    #: unconfigured.
    api_base: str = ""
    #: Authenticates as PRIVATE-TOKEN. A project access token with the `api`
    #: scope is the intended shape; CI_JOB_TOKEN cannot post notes.
    token: str = ""
    #: The numeric project ID (CI_PROJECT_ID).
    project_id: str = ""
    #: The merge request's project-scoped IID (CI_MERGE_REQUEST_IID).
    mr_iid: str = ""

    def _headers(self) -> dict[str, str]:
        return {"PRIVATE-TOKEN": self.token}

    def _mr_path(self, suffix: str = "") -> str:
        return (
            f"{self.api_base}/projects/{quote(self.project_id, safe='')}"
            f"/merge_requests/{self.mr_iid}{suffix}"
        )

    # --- summary note -----------------------------------------------------

    def upsert_comment(self, body: str, marker: str) -> None:
        """Trouve la note existante contenant `marker` et remplace son corps, ou
        crée une nouvelle note."""
        note_id = self._find_note(marker)
        if note_id:
            send_json("PUT", self._mr_path(f"/notes/{note_id}"), self._headers(), {"body": body})
            return
        send_json("POST", self._mr_path("/notes"), self._headers(), {"body": body})

    def _find_note(self, marker: str) -> int:
        for page in range(1, _MAX_PAGES + 1):
            notes = (
                get_json(self._mr_path(f"/notes?per_page=100&page={page}"), self._headers()) or []
            )
            for n in notes:
                if marker in n.get("body", ""):
                    return int(n.get("id", 0))
            if len(notes) < 100:
                break
        return 0

    # --- inline suggestions -----------------------------------------------

    def post_suggestions(
        self, summary: str, comments: list[InlineComment], head_sha: str
    ) -> SuggestionOutcome:
        """Rattache les commentaires en discussions en ligne.

        `head_sha`, quand il est non vide, est comparé à la tête actuelle de la
        MR : si la branche a bougé depuis le scan, rien n'est posté plutôt que
        d'épingler des suggestions sur des lignes qui ne disent plus ce que le
        scan a vu.
        """
        out = SuggestionOutcome()
        if not comments:
            return out

        refs = self._diff_refs()
        if head_sha and refs.head != head_sha:
            raise HTTPError(
                f"merge request head moved (scanned {head_sha[:8]}, MR is at "
                f"{refs.head[:8]}) — suggestions skipped, the next pipeline will "
                "post them"
            )

        diff_lines = self._commentable_lines()
        existing = self._existing_note_bodies()

        posted = 0
        in_batch: set[str] = set()
        for cm in comments:
            if cm.marker and (cm.marker in existing or cm.marker in in_batch):
                out.already_there += 1
                continue
            in_batch.add(cm.marker)
            if not lines_in_diff(diff_lines, cm):
                out.outside_diff += 1
                continue

            # The suggestion fence in the body is range-relative to its anchor,
            # so a multi-line fix anchors at its first line; the fence's +N
            # covers the rest.
            anchor = cm.start_line if cm.start_line > 0 else cm.line
            payload: dict[str, Any] = {
                "body": cm.body,
                "position": {
                    "position_type": "text",
                    "base_sha": refs.base,
                    "start_sha": refs.start,
                    "head_sha": refs.head,
                    "new_path": cm.path,
                    "old_path": cm.path,
                    "new_line": anchor,
                },
            }
            try:
                send_json("POST", self._mr_path("/discussions"), self._headers(), payload)
            except HTTPError as exc:
                # Each discussion is its own request; report what landed before
                # the failure so the numbers stay honest.
                out.posted = posted
                raise HTTPError(f"after posting {posted} suggestion(s): {exc}") from exc
            posted += 1
        out.posted = posted

        # The batch summary goes as a plain note, once, only when something was
        # posted — GitLab has no review object to carry it.
        if posted > 0 and summary:
            send_json("POST", self._mr_path("/notes"), self._headers(), {"body": summary})
        return out

    def _diff_refs(self) -> DiffRefs:
        mr = get_json(self._mr_path(), self._headers()) or {}
        refs = mr.get("diff_refs") or {}
        head = str(refs.get("head_sha") or "")
        if not head:
            raise HTTPError("merge request has no diff_refs yet")
        return DiffRefs(
            base=str(refs.get("base_sha") or ""),
            start=str(refs.get("start_sha") or ""),
            head=head,
        )

    def _commentable_lines(self) -> dict[str, set[int]]:
        out: dict[str, set[int]] = {}
        for page in range(1, _MAX_PAGES + 1):
            files = (
                get_json(self._mr_path(f"/diffs?per_page=100&page={page}"), self._headers()) or []
            )
            for f in files:
                out[f.get("new_path", "")] = patch_line_numbers(f.get("diff") or "")
            if len(files) < 100:
                break
        return out

    def _existing_note_bodies(self) -> str:
        """Concatène toutes les notes de la MR — notes de discussion comprises —
        pour la recherche de marqueurs."""
        parts: list[str] = []
        for page in range(1, _MAX_PAGES + 1):
            notes = (
                get_json(self._mr_path(f"/notes?per_page=100&page={page}"), self._headers()) or []
            )
            for n in notes:
                parts.append(n.get("body", ""))
                parts.append("\n")
            if len(notes) < 100:
                break
        return "".join(parts)


def from_env() -> Client:
    """Construit un client depuis les variables prédéfinies de GitLab CI.

    Le jeton est cherché sous TFPDF_GITLAB_TOKEN d'abord, pour qu'il puisse
    être une variable CI/CD limitée à cet outil, puis sous GITLAB_TOKEN.
    """
    token = os.environ.get("TFPDF_GITLAB_TOKEN") or os.environ.get("GITLAB_TOKEN", "")
    c = Client(
        api_base=os.environ.get("CI_API_V4_URL", ""),
        token=token,
        project_id=os.environ.get("CI_PROJECT_ID", ""),
        mr_iid=os.environ.get("CI_MERGE_REQUEST_IID", ""),
    )
    if not c.api_base or not c.project_id:
        raise GitLabConfigError("not running under GitLab CI (CI_API_V4_URL/CI_PROJECT_ID unset)")
    if not c.mr_iid:
        raise GitLabConfigError(
            "no merge request in this pipeline (CI_MERGE_REQUEST_IID unset) — run the "
            "scan in a merge_request pipeline"
        )
    if not c.token:
        raise GitLabConfigError(
            "no token — set TFPDF_GITLAB_TOKEN (a project access token with the api "
            "scope; CI_JOB_TOKEN cannot post notes)"
        )
    return c
