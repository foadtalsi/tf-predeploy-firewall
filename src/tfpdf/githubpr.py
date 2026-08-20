"""Publication du rapport de scan sur une pull request GitHub.

Porte internal/githubpr/comment.go et internal/githubpr/review.go.

L'API REST nue, sans SDK : c'est une poignée d'appels par pipeline, et un SDK
serait une dépendance que la CI d'autres gens devrait valider à leur place.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ._httpjson import get_json, send_json
from .forge import InlineComment, SuggestionOutcome, lines_in_diff, patch_line_numbers

#: 300 changed files is far past the point of usefulness.
_MAX_PAGES = 10

DEFAULT_API_BASE = "https://api.github.com"

#: Aliases for the forge-neutral types, so callers and tests keep reading
#: naturally — the same aliasing review.go does.
ReviewComment = InlineComment
ReviewOutcome = SuggestionOutcome


@dataclass(slots=True)
class Client:
    """Dialogue avec une pull request."""

    token: str
    owner: str
    repo: str
    pr_num: int
    #: Override for tests; defaults to the public API.
    api_base: str = ""

    def _base(self) -> str:
        return self.api_base or DEFAULT_API_BASE

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": "Bearer " + self.token,
            "Accept": "application/vnd.github+json",
        }

    # --- summary comment --------------------------------------------------

    def upsert_comment(self, body: str, marker: str) -> None:
        """Trouve sur la PR un commentaire existant contenant `marker` et remplace
        son corps, ou en crée un nouveau s'il n'y en a aucun."""
        existing_id = self._find_existing_comment(marker)
        if existing_id:
            url = f"{self._base()}/repos/{self.owner}/{self.repo}/issues/comments/{existing_id}"
            send_json("PATCH", url, self._headers(), {"body": body})
            return
        url = f"{self._base()}/repos/{self.owner}/{self.repo}/issues/{self.pr_num}/comments"
        send_json("POST", url, self._headers(), {"body": body})

    def _find_existing_comment(self, marker: str) -> int:
        url = (
            f"{self._base()}/repos/{self.owner}/{self.repo}"
            f"/issues/{self.pr_num}/comments?per_page=100"
        )
        comments = get_json(url, self._headers()) or []
        for cm in comments:
            if marker in cm.get("body", ""):
                return int(cm.get("id", 0))
        return 0

    # --- reviewers --------------------------------------------------------

    def request_reviewers(self, users: list[str], teams: list[str]) -> None:
        """Demande une relecture aux utilisateurs et groupes donnés — sert à
        imposer une seconde relecture humaine quand une découverte critique est
        présente.

        Ceci ne fait que demander la relecture ; c'est GitHub lui-même, via le
        réglage des relecteurs obligatoires de la protection de branche —
        configuré une fois sur le dépôt et non par PR — qui bloque réellement la
        fusion dessus. Sans effet, silencieusement, si les deux listes sont
        vides.
        """
        if not users and not teams:
            return
        url = (
            f"{self._base()}/repos/{self.owner}/{self.repo}/pulls/{self.pr_num}/requested_reviewers"
        )
        send_json(
            "POST",
            url,
            self._headers(),
            {"reviewers": users, "team_reviewers": teams},
        )

    # --- inline suggestions -----------------------------------------------

    def post_suggestions(
        self, summary: str, comments: list[InlineComment], commit_sha: str
    ) -> SuggestionOutcome:
        """Rattache les commentaires à la PR en une seule revue.

        Deux contraintes de GitHub façonnent ceci. D'abord, un commentaire de
        revue ne peut se poser que sur une ligne figurant dans le diff — tout
        autre cas fait rejeter la revue entière par l'API, et pas seulement le
        commentaire fautif — donc le diff est récupéré et les commentaires hors
        de lui sont écartés ici plutôt que découverts sous forme de 422.
        Ensuite, une revue ne peut pas être modifiée d'un bloc comme le
        commentaire de synthèse : réexécuter empilerait une copie fraîche de
        chaque suggestion sur la PR. Les deux sont traitées avant que quoi que
        ce soit ne soit posté.

        `commit_sha` doit être la tête de PR sur laquelle ce scan a réellement
        tourné. Le passer fait que si la branche a bougé entre-temps, GitHub
        rejette la revue au lieu d'épingler des suggestions sur des lignes qui
        ont changé depuis.

        Rend sans rien avoir posté, et sans erreur, quand tous les commentaires
        ont été écartés — le cas courant d'une réexécution sans changement.
        """
        out = SuggestionOutcome()
        if not comments:
            return out

        diff_lines = self._commentable_lines()
        existing = self._existing_review_comments()

        payload: list[dict[str, Any]] = []
        in_batch: set[str] = set()
        for cm in comments:
            # Already on the PR from an earlier push, or already in this batch
            # — two rules can reach the same conclusion about the same line.
            if cm.marker and (cm.marker in existing or cm.marker in in_batch):
                out.already_there += 1
                continue
            in_batch.add(cm.marker)
            if not lines_in_diff(diff_lines, cm):
                out.outside_diff += 1
                continue
            ac: dict[str, Any] = {
                "path": cm.path,
                "line": cm.line,
                "body": cm.body,
                "side": "RIGHT",
            }
            if 0 < cm.start_line < cm.line:
                ac["start_line"] = cm.start_line
                ac["start_side"] = "RIGHT"
            payload.append(ac)

        if not payload:
            return out

        body: dict[str, Any] = {
            "event": "COMMENT",
            "body": summary,
            "comments": payload,
        }
        if commit_sha:
            body["commit_id"] = commit_sha

        url = f"{self._base()}/repos/{self.owner}/{self.repo}/pulls/{self.pr_num}/reviews"
        send_json("POST", url, self._headers(), body)

        out.posted = len(payload)
        return out

    def _commentable_lines(self) -> dict[str, set[int]]:
        """Associe à chaque fichier modifié les numéros de lignes, dans le fichier
        d'après changement, sur lesquels GitHub acceptera un commentaire de
        revue.

        Les lignes ajoutées comme les lignes de contexte y ont droit ; seules
        les lignes supprimées non, n'ayant aucune position dans le nouveau
        fichier. Que les lignes de contexte comptent n'est pas un détail : une
        ressource sans prevent_destroy est généralement signalée sur son en-tête
        `resource "…" {` inchangé, qui n'apparaît dans le diff qu'en contexte.
        """
        out: dict[str, set[int]] = {}
        for page in range(1, _MAX_PAGES + 1):
            url = (
                f"{self._base()}/repos/{self.owner}/{self.repo}"
                f"/pulls/{self.pr_num}/files?per_page=100&page={page}"
            )
            files = get_json(url, self._headers()) or []
            for f in files:
                out[f.get("filename", "")] = patch_line_numbers(f.get("patch") or "")
            if len(files) < 100:
                break
        return out

    def _existing_review_comments(self) -> str:
        """Tous les corps de commentaires de revue en ligne déjà présents sur la
        PR, concaténés — les appelants n'y cherchent jamais que des marqueurs
        par sous-chaîne, les garder séparés n'apporterait rien."""
        parts: list[str] = []
        for page in range(1, _MAX_PAGES + 1):
            url = (
                f"{self._base()}/repos/{self.owner}/{self.repo}"
                f"/pulls/{self.pr_num}/comments?per_page=100&page={page}"
            )
            comments = get_json(url, self._headers()) or []
            for cm in comments:
                parts.append(cm.get("body", ""))
                parts.append("\n")
            if len(comments) < 100:
                break
        return "".join(parts)
