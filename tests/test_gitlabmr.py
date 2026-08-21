"""Port de internal/gitlabmr/gitlabmr_test.go, cas pour cas."""

from __future__ import annotations

from typing import Any

import pytest

from httpstub import Request, Response, StubServer
from tfpdf._httpjson import HTTPError
from tfpdf.forge import InlineComment
from tfpdf.gitlabmr import Client, GitLabConfigError, from_env

MR_PATCH = (
    '@@ -1,3 +1,4 @@\n resource "aws_db_instance" "prod" {\n'
    '-  old = 1\n+  new = 1\n+  password = "x"\n }\n'
)


def refs_ok() -> dict[str, str]:
    return {"base_sha": "b1", "start_sha": "s1", "head_sha": "h1"}


class _State:
    """Reproduit les champs du glServer du test Go."""

    def __init__(
        self,
        notes: list[dict[str, Any]] | None = None,
        diff_refs: dict[str, str] | None = None,
    ) -> None:
        self.notes = notes or []
        self.diff_refs = diff_refs or {}
        self.created: list[dict[str, Any]] = []
        self.discussions: list[dict[str, Any]] = []
        self.updated_note: dict[str, Any] | None = None

    def handler(self, r: Request) -> Response:
        if r.method == "GET" and r.path.endswith("/merge_requests/7"):
            return Response(body={"diff_refs": self.diff_refs})
        if r.method == "GET" and "/diffs" in r.path:
            if r.query.get("page") == ["1"]:
                return Response(body=[{"new_path": "main.tf", "diff": MR_PATCH}])
            return Response(body=[])
        if r.method == "GET" and "/notes" in r.path:
            return Response(body=self.notes if r.query.get("page") == ["1"] else [])
        if r.method == "PUT" and "/notes/" in r.path:
            self.updated_note = r.body
            return Response(body={"id": 1})
        if r.method == "POST" and r.path.endswith("/notes"):
            self.created.append(r.body)
            return Response(status=201, body={"id": 2})
        if r.method == "POST" and r.path.endswith("/discussions"):
            self.discussions.append(r.body)
            return Response(status=201, body={"id": "d1"})
        raise AssertionError(f"unexpected request: {r.method} {r.path}")


def _client(srv: StubServer) -> Client:
    return Client(api_base=srv.url, token="tok", project_id="42", mr_iid="7")


def test_upsert_comment_creates_then_updates() -> None:
    s = _State()
    with StubServer(s.handler) as srv:
        c = _client(srv)

        c.upsert_comment("first <!-- m -->", "<!-- m -->")
        assert len(s.created) == 1 and s.created[0]["body"] == "first <!-- m -->"

        s.notes = [{"id": 5, "body": "first <!-- m -->"}]
        c.upsert_comment("second <!-- m -->", "<!-- m -->")
        assert s.updated_note is not None
        assert s.updated_note["body"] == "second <!-- m -->"


def test_post_suggestions_anchors_at_start_line_with_diff_refs() -> None:
    """L'objet position est ce qui rend un commentaire en ligne réellement en
    ligne ; les SHA viennent des diff_refs de la MR elle-même, et l'ancre est la
    PREMIÈRE ligne du correctif, le bloc de suggestion de GitLab s'étendant vers
    le bas depuis son ancre."""
    s = _State(diff_refs=refs_ok())
    with StubServer(s.handler) as srv:
        out = _client(srv).post_suggestions(
            "summary",
            [
                InlineComment(
                    path="main.tf",
                    start_line=2,
                    line=4,
                    body="```suggestion:-0+2\nfix\n```",
                    marker="<!-- m -->",
                )
            ],
            "h1",
        )

    assert out.posted == 1, out
    pos = s.discussions[0]["position"]
    assert pos["new_line"] == 2, "the anchor is the range's first line"
    assert pos["base_sha"] == "b1"
    assert pos["start_sha"] == "s1"
    assert pos["head_sha"] == "h1"
    assert pos["new_path"] == "main.tf"
    # The batch summary is posted as a plain note.
    assert len(s.created) == 1 and "summary" in s.created[0]["body"]


def test_post_suggestions_refuses_when_the_mr_head_moved() -> None:
    """Si la branche a bougé depuis le scan, les lignes que visent les
    correctifs peuvent ne plus dire ce que le scan a vu. Refuser en bloc vaut
    mieux que poster des suggestions périmées que quelqu'un applique en un
    clic."""
    s = _State(diff_refs=refs_ok())
    with StubServer(s.handler) as srv, pytest.raises(HTTPError, match="moved"):
        _client(srv).post_suggestions(
            "s", [InlineComment(path="main.tf", line=2, body="b", marker="<!-- m -->")], "older-sha"
        )
    assert not s.discussions, "nothing may be posted against a moved head"


def test_post_suggestions_filters_outside_diff_and_duplicates() -> None:
    s = _State(diff_refs=refs_ok(), notes=[{"id": 1, "body": "earlier\n<!-- dup -->"}])
    with StubServer(s.handler) as srv:
        out = _client(srv).post_suggestions(
            "s",
            [
                InlineComment(path="main.tf", line=3, body="b", marker="<!-- dup -->"),  # there
                InlineComment(path="main.tf", line=99, body="b", marker="<!-- new -->"),  # outside
                InlineComment(path="main.tf", line=3, body="b", marker="<!-- ok -->"),  # posts
            ],
            "h1",
        )

    assert (out.posted, out.already_there, out.outside_diff) == (1, 1, 1), out


def test_from_env_explains_what_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.example.com/api/v4")
    monkeypatch.setenv("CI_PROJECT_ID", "42")
    monkeypatch.setenv("CI_MERGE_REQUEST_IID", "7")
    monkeypatch.setenv("TFPDF_GITLAB_TOKEN", "")
    monkeypatch.setenv("GITLAB_TOKEN", "")

    with pytest.raises(GitLabConfigError, match="CI_JOB_TOKEN cannot post notes"):
        from_env()

    monkeypatch.setenv("TFPDF_GITLAB_TOKEN", "tok")
    assert from_env().token == "tok"
