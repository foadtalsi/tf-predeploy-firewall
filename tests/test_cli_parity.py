"""Test différentiel de tout le CLI contre le binaire Go, de bout en bout.

Sauté à moins que le binaire Go ne soit disponible — il est compilé depuis
l'arbre voisin `core/`, qui n'existera plus une fois le port terminé. C'est le
propos : ceci est un instrument de portage, et il doit disparaître avec la chose
qu'il compare.

    cd core && go build -ldflags "-X main.version=$(python -c         'import importlib.metadata as m; print(m.version("tf-predeploy-firewall"))')         " -o /tmp/tfpdf-go ./cmd/tf-predeploy-firewall
    TFPDF_GO_BINARY=/tmp/tfpdf-go python -m pytest tests/test_cli_parity.py

Chaque test unitaire de cette suite vérifie une fonction. Celui-ci vérifie le
*produit* : l'analyse des drapeaux, le chargement de la configuration, le diff
git, la base de connaissances, le moteur, les passes de suppression et les
quatre sorties rendues, sur une seule ligne de commande.
"""

from __future__ import annotations

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
    """Un dépôt à deux commits dont la tête exerce chaque famille de règles
    statiques : le détecteur d'identifiants, les quatre catégories de
    configuration non sûre, l'absence de prevent_destroy, un attribut inconnu,
    un module non épinglé et un secret dans un .tfvars."""
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
    """Aucune variable d'intégration continue ambiante : l'un ou l'autre
    scanner essaierait sinon de poster."""
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


@pytest.mark.parametrize("artefact", ["sarif.json", "cq.json", "err"])
def test_machine_readable_output_is_byte_identical(both: Path, artefact: str) -> None:
    """SARIF, le rapport GitLab Code Quality et la ligne de couverture sur
    stderr.

    Octet pour octet, parce que des machines sont configurées contre eux. Le
    SARIF fait ~39 Ko et porte la documentation Markdown complète de chaque
    règle : un seul caractère de dérive dans l'échappement, l'ordre des clés ou
    l'indentation échoue ici.

    La version estampillée dans le pilote SARIF doit correspondre, ce qui est la
    raison pour laquelle la commande de compilation du docstring de module passe
    `-ldflags -X main.version`.
    """
    go = (both / f"go.{artefact}").read_bytes()
    py = (both / f"py.{artefact}").read_bytes()
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
    """Comparé comme un multiensemble de lignes plutôt qu'octet pour octet, et
    la raison est un défaut du côté Go.

    Go trie la table sur `(fichier, ligne)` avec `sort.Slice`, qui n'est pas
    stable. Deux découvertes sur une même ligne — une ressource porteuse d'état
    avec un mot de passe en dur reçoit à la fois `missing_lifecycle` et
    `tutorial_pattern` sur son en-tête — sortent dans l'ordre que produit
    pdqsort. C'est reproductible pour une entrée donnée et arbitraire par
    ailleurs, et une montée de version de Go pourrait réordonner un commentaire
    de PR sans aucun changement de règle derrière.

    Le côté Python trie sur `(fichier, ligne, catégorie, message)`, un ordre
    total, si bien que sa sortie est spécifiée plutôt qu'héritée. Les deux
    s'accordent donc sur chaque ligne et peuvent diverger sur l'ordre des lignes
    qui partagent un fichier et une ligne — ce que ceci vérifie précisément,
    plutôt que de le masquer.
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
    """Une clé de tri totale ne vaut la peine que si elle épingle réellement la
    sortie."""
    digests = set()
    for i in range(3):
        _run(_PY_ENTRY, repo, tmp_path, f"run{i}", "--base-ref", "HEAD~1", "--head-ref", "HEAD")
        digests.add((tmp_path / f"run{i}.md").read_text())
    assert len(digests) == 1


def test_full_repo_scan_agrees_over_the_go_fixture_corpus(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """La même comparaison sur ~70 découvertes au lieu de 10.

    Scanne l'arbre Go lui-même, dont les testdata/fixtures sont le corpus sur
    lequel les fichiers témoins sont épinglés — une surface bien plus large
    qu'un seul dépôt synthétique.
    """
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
