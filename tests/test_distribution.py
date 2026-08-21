"""Les trois fichiers qui décident si quiconque peut réellement exécuter
ceci.

Aucun d'eux n'est exercé en se servant du scanner, et tous trois échouent d'une
façon qui n'apparaît que dans le pipeline de quelqu'un d'autre :

* `action.yml` passe une liste d'arguments fixe. Un seul drapeau qu'il nomme et
  que le CLI n'accepte pas, et chaque workflow qui utilise l'action échoue au
  démarrage — y compris sur les valeurs par défaut de l'action elle-même, ce par
  quoi `--full-repo-scan=false` a bien failli passer.
* `.pre-commit-hooks.yaml` nomme un `entry:` que pre-commit exécute tel quel.
* `pyproject.toml` décide de ce qui finit dans la roue. Une roue sans les packs
  de règles s'installe parfaitement et ne trouve rien — le pire échec disponible
  pour un scanner de sécurité, parce qu'il ressemble à un dépôt propre.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import yaml

from tfpdf.cli.goflags import normalize_argv
from tfpdf.cli.main import build_parser

ROOT = Path(__file__).resolve().parent.parent


def _load_yaml(name: str) -> Any:
    return yaml.safe_load((ROOT / name).read_text(encoding="utf-8"))


_EXPRESSION = re.compile(r"\$\{\{\s*([^}]+?)\s*\}\}")


def _resolve_expressions(arg: str, inputs: dict[str, Any]) -> str:
    """Résout `${{ … }}` comme le ferait un workflow qui ne pose rien.

    Un `inputs.x` devient la valeur par défaut déclarée de x — qui, pour
    `full-repo-scan`, est la chaîne « false » et non la chaîne vide. Cette
    distinction est tout le propos : `--full-repo-scan=false` est ce que l'action
    passe à chaque vérification de PR ordinaire, et `--full-repo-scan=` est une
    erreur d'analyse dans les deux versions (Go dit `invalid boolean value ""
    for -full-repo-scan`, celle-ci dit `must be true or false, got ''`, toutes
    deux sortant en 2). Substituer aveuglément aurait testé le chemin d'erreur en
    l'appelant le chemin heureux.

    Tout le reste — `github.token`,
    `github.event.pull_request.base.ref` — se résout à vide, ce qu'il vaut hors
    d'un événement de PR.
    """

    def repl(m: re.Match[str]) -> str:
        expr = m.group(1)
        if expr.startswith("inputs."):
            declared = inputs.get(expr.removeprefix("inputs."), {})
            default = str(declared.get("default", ""))
            # A default can itself be an expression (github.*), so recurse.
            return _resolve_expressions(default, inputs) if "${{" in default else default
        return ""

    return _EXPRESSION.sub(repl, arg)


def test_the_action_argument_list_is_accepted_by_the_cli() -> None:
    action = _load_yaml("action.yml")
    inputs = action["inputs"]
    raw = [_resolve_expressions(a, inputs) for a in action["runs"]["args"]]

    assert "--full-repo-scan=false" in raw, (
        "the action's own default has to be the case that is tested"
    )

    args = build_parser().parse_args(normalize_argv(raw))

    # The empty strings have to mean "not given", not "a file called ''".
    assert args.sarif_output == ""
    assert args.plan_json == ""
    assert args.baseline == ""
    assert args.full_repo_scan is False


def test_an_empty_boolean_input_fails_the_same_way_the_go_build_did() -> None:
    """`full-repo-scan: ""` dans un workflow — une condition qui s'est évaluée
    à rien — atteint le CLI en `--full-repo-scan=`.

    Go le rejette (`invalid boolean value "" for -full-repo-scan`, sortie 2) et
    celui-ci aussi, avec un message qui dit ce qui était attendu. Épinglé parce
    que la forme à valeur optionnelle qui fait marcher `=false` est exactement le
    mécanisme qui aurait pu être écrit de façon à accepter silencieusement `=`
    comme vrai.
    """
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--full-repo-scan="])
    assert exc.value.code == 2


def test_every_action_input_reaches_the_cli() -> None:
    """Une entrée documentée mais câblée à rien est pire qu'une entrée
    manquante : l'auteur du workflow la pose, ne voit aucune erreur, et obtient
    un scan qui l'a ignoré."""
    action = _load_yaml("action.yml")
    args_text = " ".join(action["runs"]["args"])
    env_text = " ".join(f"{k}: {v}" for k, v in action["runs"]["env"].items())
    wired = args_text + " " + env_text

    for name in action["inputs"]:
        assert f"inputs.{name}" in wired, f"input {name!r} is documented but unused"


def test_the_action_environment_variables_are_ones_the_cli_reads() -> None:
    action = _load_yaml("action.yml")
    read_by_cli = {
        "GITHUB_TOKEN",
        "SCANNER_BLOCK_THRESHOLD",
        "SCANNER_PLAN_BLAST_RADIUS_THRESHOLD",
        "SCANNER_COST_IMPACT_THRESHOLD_USD",
        "SCANNER_SUGGESTIONS",
        "SCANNER_CONFIG",
        "TFPDF_LICENSE_KEY",
        "TFPDF_LICENSE_API_BASE",
        "TFPDF_PROVIDERS",
        "TFPDF_BASELINE",
        "TFPDF_RULES",
        "TFPDF_CACHE_DIR",
    }
    for name in action["runs"]["env"]:
        assert name in read_by_cli, f"the action sets {name}, which nothing reads"


def test_the_hook_entry_is_a_command_the_cli_accepts() -> None:
    hooks = _load_yaml(".pre-commit-hooks.yaml")
    assert len(hooks) == 1
    hook = hooks[0]

    assert hook["language"] == "python", (
        "the Go build used language: golang; a Python package is installed into "
        "pre-commit's own venv instead"
    )
    assert hook["pass_filenames"] is False, (
        "the scanner reads the git index itself, so filenames would be ignored "
        "arguments the parser has nowhere to put"
    )

    entry = shlex.split(hook["entry"])
    assert entry[0] == "tf-predeploy-firewall", "must match a console script"
    args = build_parser().parse_args(normalize_argv(entry[1:]))
    assert args.staged is True


def test_the_hook_file_filter_covers_tfvars() -> None:
    """Un commit qui n'ajoute que terraform.tfvars est le plus précieux de tous
    pour ce hook — ce fichier est là où vivent les valeurs, donc là où atterrit
    un secret. `\\.tf` ancré à la fin ne lui correspond pas."""
    import re

    pattern = re.compile(_load_yaml(".pre-commit-hooks.yaml")[0]["files"])
    for path in (
        "main.tf",
        "terraform.tfvars",
        "prod.tfvars.json",
        "terragrunt.hcl",
        "modules/rds/main.tf",
    ):
        assert pattern.search(path), f"{path} must reach the hook"
    for path in ("README.md", "main.tf.tmpl", "notes.txt"):
        assert not pattern.search(path), f"{path} must not"


def test_the_console_scripts_point_at_functions_that_exist() -> None:
    """Une faute de frappe ici se compile et s'installe proprement, et échoue à
    la première utilisation."""
    import importlib
    import tomllib

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    entries = document["project"]["scripts"]
    assert set(entries) == {"tf-predeploy-firewall", "tfpdf-genpack"}

    for name, target in entries.items():
        module_name, func_name = target.split(":")
        module = importlib.import_module(module_name)
        assert callable(getattr(module, func_name)), f"{name} -> {target} is not callable"


@pytest.mark.parametrize(
    "resource",
    [
        "tfpdf/ruledef/rules.py",
        "tfpdf/config/default.yml",
        "tfpdf/schema/data/pack_aws_base.json.gz",
        "tfpdf/schema/data/pack_azurerm_base.json.gz",
        "tfpdf/schema/curated/base_pack_types.json",
        "tfpdf/schema/curated/critical_stateful_resources.json",
        "tfpdf/schema/curated/aws_pricing.json",
    ],
)
def test_the_detection_data_is_reachable_as_package_data(resource: str) -> None:
    """Lu comme le paquet installé le lit — à travers le système d'import, pas
    par un chemin relatif à l'arbre source. Un fichier qui ne se résout que
    depuis une copie de travail est un fichier que la roue ne livre pas
    vraiment."""
    from importlib import resources as importlib_resources

    package, _, filename = resource.rpartition("/")
    package = package.replace("/", ".")
    assert importlib_resources.files(package).joinpath(filename).is_file()


def test_the_runtime_dependency_list_is_still_one_line() -> None:
    """Le scanner tourne dans l'intégration continue des autres. Chaque
    dépendance est une chose de plus qui peut casser leur pipeline ou retenir
    leur revue de chaîne d'approvisionnement, ce qui est la raison pour laquelle
    l'analyseur HCL est dans l'arbre. C'est l'assertion qui garde cet argument
    honnête."""
    import tomllib

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = document["project"]["dependencies"]
    assert len(deps) == 1, f"runtime dependencies grew to {deps}"
    assert deps[0].startswith("PyYAML")


def test_the_dockerfile_installs_git_and_entrypoints_the_scanner() -> None:
    """Le scanner lit un diff git depuis une copie de travail locale, ce qui est
    la raison pour laquelle il n'a besoin d'aucun identifiant cloud — et la
    raison pour laquelle une image sans git est une image qui ne peut rien
    scanner."""
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "git" in text
    assert 'ENTRYPOINT ["tf-predeploy-firewall"]' in text
    # Everything the build stage copies has to exist, or the image fails to
    # build on a runner rather than here.
    for copied in ("pyproject.toml", "README.md", "src"):
        assert (ROOT / copied).exists(), f"the Dockerfile COPYs {copied}, which is missing"
