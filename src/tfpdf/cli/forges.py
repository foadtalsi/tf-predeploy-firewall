"""Le choix de la forge depuis l'environnement CI, et tout ce qui y est posté.

Porte la moitié « forge » de cmd/tf-predeploy-firewall/main.go.

Chaque fonction ici est au mieux-effort. Elles s'exécutent après le commentaire
de synthèse, qui porte déjà toutes les découvertes, donc un échec coûte le
confort et rien d'autre — aucune ne touche au code de sortie. C'est la décision
de blocage qui est le mécanisme d'application.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .. import githubpr, gitlabmr, report
from ..forge import InlineComment
from ..report.finding import Finding, Severity
from .config import Config

#: Caps how many inline comments one review will carry. Past a certain point a
#: wall of bot comments is skimmed rather than read, and the summary comment
#: already lists everything — so the cap trades completeness for the
#: suggestions actually being looked at. Whatever it drops is logged, never
#: dropped quietly.
MAX_INLINE_SUGGESTIONS = 20

#: Overrides the GitHub API base URL for tests only (empty in production, which
#: makes the client default to the real api.github.com). Never set outside a
#: test.
github_api_base_for_test = ""


class ForgeError(RuntimeError):
    """L'environnement CI ambiant ne décrit aucun changement où poster."""


class _Forge(Protocol):
    def upsert_comment(self, body: str, marker: str) -> None: ...


def _warn(msg: str) -> None:
    print("tf-predeploy-firewall: " + msg, file=sys.stderr)


def repo_full_name_from_env() -> str:
    """L'identité org/dépôt utilisée pour la licence — usage, dérogations,
    politique d'organisation — sur la CI où tourne cette exécution.

    Le plan de contrôle s'indexe sur la chaîne elle-même, donc
    « groupe/projet » venu de GitLab vaut autant que « proprio/dépôt » venu de
    GitHub.
    """
    return os.environ.get("GITHUB_REPOSITORY") or os.environ.get("CI_PROJECT_PATH", "")


def default_base_ref() -> str:
    """La branche cible de la PR ou MR, depuis la CI qui la fournit.

    Les deux livrent un nom de branche nu ; le préfixe `origin/` est ce qu'un
    checkout récupéré possède réellement.
    """
    if v := os.environ.get("GITHUB_BASE_REF"):
        return "origin/" + v.removeprefix("origin/")
    if v := os.environ.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME"):
        return "origin/" + v
    return "origin/main"


def default_post_comment() -> bool:
    """Poster quand un jeton pour la forge ambiante est présent."""
    if os.environ.get("GITLAB_CI"):
        return bool(os.environ.get("TFPDF_GITLAB_TOKEN") or os.environ.get("GITLAB_TOKEN"))
    return bool(os.environ.get("GITHUB_TOKEN"))


def _pr_number_from_event() -> int:
    if v := os.environ.get("PR_NUMBER"):
        try:
            return int(v)
        except ValueError as exc:
            raise ForgeError(f"PR_NUMBER is not a number: {v!r}") from exc

    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        raise ForgeError("GITHUB_EVENT_PATH not set and PR_NUMBER not provided")
    try:
        data = Path(event_path).read_bytes()
    except OSError as exc:
        raise ForgeError(f"reading GITHUB_EVENT_PATH: {exc}") from exc
    try:
        event = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ForgeError(f"parsing event payload: {exc}") from exc

    number = 0
    if isinstance(event, dict):
        pr = event.get("pull_request")
        if isinstance(pr, dict):
            number = int(pr.get("number") or 0)
    if number == 0:
        raise ForgeError("event payload has no pull_request.number (not a pull_request event?)")
    return number


def head_sha_from_event() -> str:
    """Le commit de tête de la PR, depuis la charge utile de l'événement
    Actions.

    `GITHUB_SHA` n'est délibérément pas utilisé : sur un événement
    pull_request il pointe sur le commit de fusion éphémère, qui n'est pas un
    commit de la PR et que GitHub refuse comme commit_id d'une revue. Un
    résultat vide convient : GitHub rattache alors la revue au dernier commit
    en date.
    """
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return ""
    try:
        event = json.loads(Path(event_path).read_bytes())
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(event, dict):
        return ""
    pr = event.get("pull_request")
    if not isinstance(pr, dict):
        return ""
    head = pr.get("head")
    if not isinstance(head, dict):
        return ""
    return str(head.get("sha") or "")


def github_pr_client() -> githubpr.Client:
    """Construit un client depuis le contexte GitHub Actions — partagé par
    `post_to_pr` et `request_second_reviewer_if_critical`, pour que les deux
    échouent de la même façon quand ce contexte n'est pas disponible, par
    exemple hors d'un événement de PR."""
    token = os.environ.get("GITHUB_TOKEN", "")
    repo_full = os.environ.get("GITHUB_REPOSITORY", "")
    if not token or not repo_full:
        raise ForgeError("GITHUB_TOKEN/GITHUB_REPOSITORY not set")
    parts = repo_full.split("/", 1)
    if len(parts) != 2:
        raise ForgeError(f"unexpected GITHUB_REPOSITORY format: {repo_full}")

    return githubpr.Client(
        token=token,
        owner=parts[0],
        repo=parts[1],
        pr_num=_pr_number_from_event(),
        api_base=github_api_base_for_test,
    )


def active_forge() -> tuple[_Forge, str]:
    """La forge, et le SHA de tête sur lequel le scan a tourné (vide quand il
    est indéterminable).

    GitLab CI quand ses variables prédéfinies sont présentes, GitHub sinon —
    le défaut historique, et ce que fournit action.yml.
    """
    if os.environ.get("GITLAB_CI"):
        try:
            client = gitlabmr.from_env()
        except gitlabmr.GitLabConfigError as exc:
            raise ForgeError(str(exc)) from exc
        return client, os.environ.get("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA", "")
    return github_pr_client(), head_sha_from_event()


def suggestion_body_for() -> Callable[[Finding], str]:
    """Le rendu correspondant à la grammaire de suggestion de la forge active —
    la seule chose sur laquelle les deux hôtes sont réellement en désaccord."""
    if os.environ.get("GITLAB_CI"):
        return report.gitlab_suggestion_body
    return report.review_comment_body


def post_to_pr(body: str) -> None:
    """Met à jour ou crée le rapport en commentaire de PR ou MR, sur la forge à
    laquelle appartient l'environnement CI de cette exécution."""
    forge_client, _ = active_forge()
    forge_client.upsert_comment(body, report.MARKER)


def post_suggestions(findings: list[Finding]) -> None:
    """Poste en commentaires de revue en ligne les correctifs applicables tels
    quels.

    C'est la différence entre dire à quelqu'un quoi écrire et le laisser
    cliquer sur un bouton.
    """
    render = suggestion_body_for()
    comments: list[InlineComment] = []
    dropped = 0

    for f in findings:
        # An accepted finding isn't something to hand someone a fix for.
        if f.waived or f.fix is None:
            continue
        if len(comments) >= MAX_INLINE_SUGGESTIONS:
            dropped += 1
            continue
        comments.append(
            InlineComment(
                path=f.file,
                start_line=f.fix.start_line,
                line=f.fix.end_line,
                body=render(f),
                marker=report.fix_marker(f),
            )
        )

    if not comments:
        return
    if dropped:
        _warn(
            f"{dropped} applicable fix(es) beyond the first {MAX_INLINE_SUGGESTIONS} "
            "were not posted inline; they are all in the summary comment"
        )

    try:
        client, sha = active_forge()
    except ForgeError as exc:
        _warn(f"skipping inline suggestions: {exc}")
        return

    # No report.MARKER here: that marker belongs to the upserted summary
    # comment, and a review body is a different object on a different endpoint.
    # Duplicate suggestions are prevented per-comment instead.
    summary = (
        f"**TF Pre-Deploy Firewall** — {len(comments)} fix(es) below can be applied "
        "with the **Commit suggestion** button. They are generated, not reviewed by a "
        "human; read each one before applying it."
    )

    try:
        outcome = client.post_suggestions(summary, comments, sha)  # type: ignore[attr-defined]
    except Exception as exc:
        _warn(f"posting inline suggestions failed: {exc}")
        return

    if outcome.posted:
        _warn(f"posted {outcome.posted} inline suggestion(s)")
    if outcome.outside_diff:
        _warn(
            f"{outcome.outside_diff} fix(es) target lines this PR doesn't touch, so the "
            "host can't show them inline; see the summary comment"
        )


def request_second_reviewer_if_critical(findings: list[Finding], cfg: Config) -> None:
    """Demande une relecture aux utilisateurs et groupes configurés dès qu'au
    moins une découverte de sévérité critique est présente.

    Au mieux-effort : un échec ici — l'un des identifiants configurés n'étant
    pas collaborateur du dépôt, par exemple — est journalisé et n'affecte
    jamais le code de sortie. Le blocage et la sortie en 1 dus au seuil sont le
    véritable mécanisme d'application ; ceci n'est qu'un coup de coude poli
    par-dessus.
    """
    if not cfg.require_second_reviewer_users and not cfg.require_second_reviewer_teams:
        return
    if os.environ.get("GITLAB_CI"):
        # GitLab's native mechanism for this is approval rules, configured once
        # on the project — better than anything this tool could do per-MR, so it
        # points there instead of half-imitating it.
        _warn(
            "require_second_reviewer_* is GitHub-only — on GitLab, use a merge request "
            "approval rule (Settings → Merge requests → Approvals)"
        )
        return
    if not any(not f.waived and f.severity is Severity.CRITICAL for f in findings):
        return

    try:
        client = github_pr_client()
    except ForgeError as exc:
        _warn(f"skipping second-reviewer request: {exc}")
        return
    try:
        client.request_reviewers(
            cfg.require_second_reviewer_users, cfg.require_second_reviewer_teams
        )
    except Exception as exc:
        _warn(f"requesting second reviewer failed: {exc}")
