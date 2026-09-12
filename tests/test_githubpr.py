"""GitHub summary and inline-review client tests."""

from __future__ import annotations

from typing import Any

import pytest

from httpstub import Request, Response, StubServer
from tfpdf._httpjson import HTTPError
from tfpdf.githubpr import Client, ReviewComment

TWO_HUNK_PATCH = (
    '@@ -1,3 +1,4 @@\n resource "aws_db_instance" "prod" {\n'
    '-  old = 1\n+  new = 1\n+  password = "x"\n }\n'
    "@@ -20,2 +21,3 @@\n context\n+added\n"
)


def _client(srv: StubServer) -> Client:
    return Client(token="test-token", owner="owner", repo="repo", pr_num=42, api_base=srv.url)


# --- comment.go --------------------------------------------------------------


def test_upsert_comment_creates_when_none_exists() -> None:
    def handler(r: Request) -> Response:
        if r.method == "GET" and r.path.endswith("/comments"):
            return Response(body=[])  # no existing comments
        if r.method == "POST":
            return Response(status=201, body={"id": 1})
        raise AssertionError(f"unexpected request: {r.method} {r.path}")

    with StubServer(handler) as srv:
        _client(srv).upsert_comment("hello <!-- marker -->", "<!-- marker -->")
        posted = [r for r in srv.requests if r.method == "POST"]
        assert len(posted) == 1
        assert posted[0].body == {"body": "hello <!-- marker -->"}


def test_upsert_comment_updates_existing() -> None:
    def handler(r: Request) -> Response:
        if r.method == "GET":
            return Response(body=[{"id": 99, "body": "old body <!-- marker -->"}])
        if r.method == "PATCH":
            return Response(body={"id": 99})
        raise AssertionError(f"unexpected request: {r.method} {r.path}")

    with StubServer(handler) as srv:
        _client(srv).upsert_comment("new body <!-- marker -->", "<!-- marker -->")
        patched = [r for r in srv.requests if r.method == "PATCH"]
        assert len(patched) == 1
        assert patched[0].body == {"body": "new body <!-- marker -->"}
        assert patched[0].path.endswith("/issues/comments/99")


def test_upsert_comment_auth_header() -> None:
    def handler(r: Request) -> Response:
        if r.method == "GET":
            return Response(body=[])
        return Response(status=201, body={"id": 1})

    with StubServer(handler) as srv:
        _client(srv).upsert_comment("body", "marker")
        assert srv.requests[0].headers["Authorization"] == "Bearer test-token"


def test_request_reviewers_sends_users_and_teams() -> None:
    with StubServer(lambda r: Response(status=201, body={})) as srv:
        _client(srv).request_reviewers(["alice"], ["security-team"])
        request = srv.requests[0]
        assert request.path == "/repos/owner/repo/pulls/42/requested_reviewers"
        assert request.body == {"reviewers": ["alice"], "team_reviewers": ["security-team"]}


def test_request_reviewers_no_op_when_both_empty() -> None:
    with StubServer(lambda r: Response(status=201, body={})) as srv:
        _client(srv).request_reviewers([], [])
        assert srv.calls == 0, "expected no HTTP call when both reviewer lists are empty"


def test_request_reviewers_propagates_error_status() -> None:
    def handler(r: Request) -> Response:
        return Response(
            status=422,
            body={"message": "Reviews may only be requested from collaborators"},
        )

    with StubServer(handler) as srv, pytest.raises(HTTPError, match="collaborators"):
        _client(srv).request_reviewers(["not-a-collaborator"], [])


# --- review.go ---------------------------------------------------------------


def _review_handler(
    patches: dict[str, str] | None = None,
    existing_bodies: list[str] | None = None,
) -> tuple[Any, dict[str, Any]]:
    """Stub the three review endpoints and capture the submitted review body."""
    patches = patches if patches is not None else {}
    existing_bodies = existing_bodies or []
    captured: dict[str, Any] = {}

    def handler(r: Request) -> Response:
        if r.method == "GET" and r.path.endswith("/files"):
            if r.query.get("page") == ["1"]:
                return Response(body=[{"filename": n, "patch": p} for n, p in patches.items()])
            return Response(body=[])
        if r.method == "GET" and r.path.endswith("/comments"):
            if r.query.get("page") == ["1"]:
                return Response(body=[{"body": b} for b in existing_bodies])
            return Response(body=[])
        if r.method == "POST" and r.path.endswith("/reviews"):
            captured["review"] = r.body
            return Response(body={"id": 1})
        raise AssertionError(f"unexpected request: {r.method} {r.path}")

    return handler, captured


def test_patch_line_numbers_counts_added_and_context_but_not_deleted() -> None:
    from tfpdf.forge import patch_line_numbers

    got = patch_line_numbers(TWO_HUNK_PATCH)
    # First hunk starts at new-file line 1: header(1), new(2), password(3), }(4).
    # The deleted "old = 1" must not consume a number.
    assert {1, 2, 3, 4} <= got
    # Second hunk starts at 21: context(21), added(22).
    assert {21, 22} <= got
    # Nothing between the hunks exists in the diff.
    assert not ({5, 20, 23} & got)


def test_post_suggestions_comments_on_a_context_line() -> None:
    """Lifecycle findings may anchor to unchanged resource-header context lines."""
    handler, captured = _review_handler({"main.tf": TWO_HUNK_PATCH})

    with StubServer(handler) as srv:
        out = _client(srv).post_suggestions(
            "summary",
            [ReviewComment(path="main.tf", line=1, body="fix me", marker="<!-- m1 -->")],
            "abc123",
        )

    assert out.posted == 1, out
    review = captured["review"]
    assert review["commit_id"] == "abc123", "the review must pin to the scanned head"
    assert review["event"] == "COMMENT", (
        "anything else leaves a pending review only its author can see"
    )
    first = review["comments"][0]
    assert first["side"] == "RIGHT"
    assert "start_line" not in first, "GitHub rejects start_line == line"


def test_post_suggestions_drops_comments_outside_the_diff() -> None:
    """Filter unsupported lines before posting; one invalid comment can reject the whole review."""
    handler, captured = _review_handler({"main.tf": TWO_HUNK_PATCH})

    with StubServer(handler) as srv:
        out = _client(srv).post_suggestions(
            "summary",
            [
                ReviewComment(path="main.tf", line=3, body="in diff", marker="<!-- m1 -->"),
                ReviewComment(path="main.tf", line=99, body="not in diff", marker="<!-- m2 -->"),
                ReviewComment(path="untouched.tf", line=1, body="not in PR", marker="<!-- m3 -->"),
            ],
            "",
        )

    assert (out.posted, out.outside_diff) == (1, 2), out
    assert len(captured["review"]["comments"]) == 1


def test_post_suggestions_skips_suggestions_already_on_the_pr() -> None:
    """Skip existing suggestions so repeated pushes do not duplicate reviews."""
    handler, captured = _review_handler(
        {"main.tf": TWO_HUNK_PATCH}, ["some earlier comment\n<!-- m1 -->\n"]
    )

    with StubServer(handler) as srv:
        out = _client(srv).post_suggestions(
            "summary",
            [ReviewComment(path="main.tf", line=3, body="already there", marker="<!-- m1 -->")],
            "",
        )

    assert (out.already_there, out.posted) == (1, 0), out
    assert "review" not in captured, "no review when every comment is a duplicate"


def test_post_suggestions_deduplicates_within_one_review() -> None:
    """Deduplicate identical comments within a single review."""
    handler, _ = _review_handler({"main.tf": TWO_HUNK_PATCH})
    same = ReviewComment(path="main.tf", line=3, body="fix", marker="<!-- m1 -->")

    with StubServer(handler) as srv:
        out = _client(srv).post_suggestions("summary", [same, same], "")

    assert (out.posted, out.already_there) == (1, 1), out


def test_post_suggestions_no_requests_when_there_is_nothing_to_post() -> None:
    handler, _ = _review_handler()
    with StubServer(handler) as srv:
        _client(srv).post_suggestions("summary", [], "")
        assert srv.calls == 0, "expected no HTTP traffic at all"


def test_post_suggestions_multi_line_range_sends_start_line() -> None:
    handler, captured = _review_handler({"main.tf": TWO_HUNK_PATCH})

    with StubServer(handler) as srv:
        _client(srv).post_suggestions(
            "summary",
            [
                ReviewComment(
                    path="main.tf", start_line=2, line=4, body="range", marker="<!-- m -->"
                )
            ],
            "",
        )

    first = captured["review"]["comments"][0]
    assert (first["start_line"], first["line"]) == (2, 4)
    assert first["start_side"] == "RIGHT", "start_side must accompany start_line"


def test_post_suggestions_rejects_a_range_that_leaves_the_diff() -> None:
    """Reject replacement ranges only partly covered by the diff."""
    handler, _ = _review_handler({"main.tf": TWO_HUNK_PATCH})

    with StubServer(handler) as srv:
        out = _client(srv).post_suggestions(
            "summary",
            [
                ReviewComment(
                    path="main.tf", start_line=3, line=6, body="half out", marker="<!-- m -->"
                )
            ],
            "",
        )

    assert out.outside_diff == 1, out


def test_post_suggestions_propagates_api_failure() -> None:
    """Preserve actionable API errors for the caller's nonfatal warning."""

    def handler(r: Request) -> Response:
        if r.method == "GET" and r.path.endswith("/files"):
            return Response(body=[{"filename": "main.tf", "patch": TWO_HUNK_PATCH}])
        if r.method == "GET":
            return Response(body=[])
        return Response(status=422, body={"message": "commit_id is not part of the pull request"})

    with StubServer(handler) as srv, pytest.raises(HTTPError, match="commit_id is not part"):
        _client(srv).post_suggestions(
            "summary", [ReviewComment(path="main.tf", line=1, body="x")], "stale-sha"
        )


def test_post_suggestions_empty_diff_posts_nothing_and_succeeds() -> None:
    """An empty diff has no commentable lines and requires no review request."""
    handler, captured = _review_handler({})

    with StubServer(handler) as srv:
        out = _client(srv).post_suggestions(
            "summary",
            [ReviewComment(path="main.tf", line=1, body="x", marker="<!-- m -->")],
            "",
        )

    assert (out.posted, out.outside_diff) == (0, 1), out
    assert "review" not in captured
