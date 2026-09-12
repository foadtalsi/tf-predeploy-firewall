"""Compare the Python CLI with a historical Go scanner end to end.

Set TFPDF_GO_BINARY to a version-stamped oracle binary; see CONTRIBUTING.md
and .github/workflows/ci.yml for the pinned build command. Without a binary,
these tests skip. The former neighboring Go checkout is optional.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest

GO_BINARY = os.environ.get("TFPDF_GO_BINARY", "")

pytestmark = pytest.mark.skipif(
    not GO_BINARY or not Path(GO_BINARY).exists(),
    reason="set TFPDF_GO_BINARY to a built Go scanner to run the CLI parity test",
)

_PY_ENTRY = [sys.executable, "-c", "from tfpdf.cli.main import run; run()"]

_HEAD_TF = """resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_db_instance" "prod" {
  identifier          = "prod-db"
  username            = "admin"
  password            = "SuperSecret123!"
  engine              = "postgres"
  publicly_accessible = true
  storage_encrypted   = false
}

resource "aws_security_group" "web" {
  name = "web-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "my-test-bucket"
  acll   = "private"
}

module "rds" {
  source = "terraform-aws-modules/rds/aws"
}
"""


def _git(dir_: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=dir_, capture_output=True, check=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Build a two-commit repository exercising each static rule family and variable-file checks."""
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@e.com")
    _git(tmp_path, "config", "user.name", "t")

    (tmp_path / "main.tf").write_text(
        'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
    )
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "base")

    (tmp_path / "main.tf").write_text(_HEAD_TF)
    (tmp_path / "terraform.tfvars").write_text('db_password = "hunter2-plaintext"\n')
    _git(tmp_path, "add", "-A")
    _git(tmp_path, "commit", "-qm", "head")
    return tmp_path


def _clean_env() -> dict[str, str]:
    """Remove ambient CI variables so neither scanner tries to publish comments."""
    return {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("GITHUB_", "GITLAB_", "CI_", "TFPDF_", "SCANNER_"))
    }


def _run(cmd: list[str], repo: Path, out_dir: Path, tag: str, *extra: str) -> int:
    proc = subprocess.run(
        [
            *cmd,
            "--repo-dir",
            str(repo),
            "--config",
            os.devnull,
            "--sarif-output",
            str(out_dir / f"{tag}.sarif.json"),
            "--codequality-output",
            str(out_dir / f"{tag}.cq.json"),
            *extra,
        ],
        capture_output=True,
        text=True,
        env=_clean_env(),
        check=False,
    )
    (out_dir / f"{tag}.md").write_text(proc.stdout)
    (out_dir / f"{tag}.err").write_text(proc.stderr)
    return proc.returncode


@pytest.fixture
def both(repo: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("parity")
    args = ("--base-ref", "HEAD~1", "--head-ref", "HEAD")
    go_code = _run([GO_BINARY], repo, out, "go", *args)
    py_code = _run(_PY_ENTRY, repo, out, "py", *args)
    assert go_code == py_code, f"exit codes differ: go={go_code} py={py_code}"
    assert go_code == 1, "this fixture must block"
    return out


#: Rules this scanner retired on purpose while the Go oracle still lists them.
#:
#: `cost_impact` was removed in a7d5552 together with the cost estimates. It was
#: the last rule, so removing it shifts no `ruleIndex`; if a retired rule were not
#: last, the results would stop matching and this comparison would fail, which is
#: the right outcome. Delete an entry if its rule comes back.
RETIRED_SARIF_RULES = frozenset({"cost_impact"})


def _without_retired_rules(sarif: bytes) -> dict[str, object]:
    """The Go oracle's SARIF without the rules this scanner retired on purpose."""
    document = json.loads(sarif)
    for run in document["runs"]:
        driver = run["tool"]["driver"]
        driver["rules"] = [
            rule for rule in driver["rules"] if rule["id"] not in RETIRED_SARIF_RULES
        ]
    return document


@pytest.mark.parametrize("artefact", ["sarif.json", "cq.json", "err"])
def test_machine_readable_output_is_byte_identical(both: Path, artefact: str) -> None:
    """Compare SARIF, Code Quality, and coverage output against the Go oracle byte for byte, except
    for SARIF rules this scanner retired on purpose. Match the oracle's stamped version to the
    installed Python package.
    """
    go = (both / f"go.{artefact}").read_bytes()
    py = (both / f"py.{artefact}").read_bytes()
    if artefact == "sarif.json":
        # Retired rules are the one deliberate difference from the Go oracle. Every other rule,
        # every result and every ruleIndex must still match.
        listed = {
            rule["id"] for run in json.loads(py)["runs"] for rule in run["tool"]["driver"]["rules"]
        }
        assert not listed & RETIRED_SARIF_RULES, "a retired rule is listed again"
        assert _without_retired_rules(go) == json.loads(py)
        return
    assert go == py


def _rows(path: Path) -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("| ") or "|---" in line:
            continue
        cells = tuple(c.strip() for c in line.strip().strip("|").split("|"))
        if len(cells) >= 6 and cells[0].split()[-1] in (
            "low",
            "medium",
            "high",
            "critical",
        ):
            out.append(cells)
    return out


def test_the_pr_comment_reports_exactly_the_same_findings(both: Path) -> None:
    """Compare report lines as a multiset: historical Go sorting leaves equal file/line ties
    unstable, while Python uses a total sort order.
    """
    go, py = _rows(both / "go.md"), _rows(both / "py.md")

    assert len(go) == len(py)
    assert Counter(go) == Counter(py), "the same findings, exactly"

    key = [(r[1], int(r[2])) for r in go]
    assert key == [(r[1], int(r[2])) for r in py], (
        "the (file, line) sequence is identical — any difference is inside a group "
        "sharing one, never a finding in the wrong place"
    )


def test_the_python_report_is_stable_across_runs(repo: Path, tmp_path: Path) -> None:
    """Pin deterministic report ordering across repeated scans."""
    digests = set()
    for i in range(3):
        _run(_PY_ENTRY, repo, tmp_path, f"run{i}", "--base-ref", "HEAD~1", "--head-ref", "HEAD")
        digests.add((tmp_path / f"run{i}.md").read_text())
    assert len(digests) == 1


def test_full_repo_scan_agrees_over_the_go_fixture_corpus(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Compare the larger historical Go fixture corpus when its checkout is available."""
    core = Path(__file__).resolve().parents[2] / "core"
    if not (core / ".git").exists() or shutil.which("git") is None:
        pytest.skip("the sibling core/ git tree is not available")

    out = tmp_path_factory.mktemp("fullrepo")
    go_code = _run([GO_BINARY], core, out, "go", "--full-repo-scan")
    py_code = _run(_PY_ENTRY, core, out, "py", "--full-repo-scan")
    assert go_code == py_code

    assert (out / "go.sarif.json").read_bytes() == (out / "py.sarif.json").read_bytes()
    assert (out / "go.cq.json").read_bytes() == (out / "py.cq.json").read_bytes()

    go, py = _rows(out / "go.md"), _rows(out / "py.md")
    assert len(go) > 50, "expected the fixture corpus to produce a substantial report"
    assert Counter(go) == Counter(py)
    assert [(r[1], int(r[2])) for r in go] == [(r[1], int(r[2])) for r in py]
