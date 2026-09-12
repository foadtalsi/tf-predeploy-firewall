"""Check distribution contracts: Action arguments, pre-commit entry point, and packaged detection
data must work after installation.
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
    """Resolve Action input expressions using declared defaults; other expressions are empty
    outside PR context.
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
    """An empty attached boolean must fail rather than silently become true."""
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--full-repo-scan="])
    assert exc.value.code == 2


def test_every_action_input_reaches_the_cli() -> None:
    """Every advertised Action input must reach a recognized CLI option."""
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
    """The hook must run on variable-file-only commits."""
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
    """Installed console entry points must resolve to real functions."""
    import importlib
    import tomllib

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    entries = document["project"]["scripts"]
    # The scanner has one console entry point; pack generation belongs to separate tooling.
    assert set(entries) == {"tf-predeploy-firewall"}

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
    ],
)
def test_the_detection_data_is_reachable_as_package_data(resource: str) -> None:
    """Load detection data through package resources, as an installed wheel does."""
    from importlib import resources as importlib_resources

    package, _, filename = resource.rpartition("/")
    package = package.replace("/", ".")
    assert importlib_resources.files(package).joinpath(filename).is_file()


def test_the_runtime_dependency_list_is_still_one_line() -> None:
    """Keep the mandatory runtime dependency list minimal."""
    import tomllib

    document = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = document["project"]["dependencies"]
    assert len(deps) == 1, f"runtime dependencies grew to {deps}"
    assert deps[0].startswith("PyYAML")


def test_the_dockerfile_installs_git_and_entrypoints_the_scanner() -> None:
    """The container needs Git and the scanner's console entry point."""
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "git" in text
    assert 'ENTRYPOINT ["tf-predeploy-firewall"]' in text
    # Everything the build stage copies has to exist, or the image fails to
    # build on a runner rather than here.
    for copied in ("pyproject.toml", "README.md", "src"):
        assert (ROOT / copied).exists(), f"the Dockerfile COPYs {copied}, which is missing"


def test_the_pack_generator_does_not_ship_with_the_scanner() -> None:
    """Pack generation belongs to separate tooling and must not ship as a scanner entry point."""
    assert not (ROOT / "src" / "tfpdf" / "genpack").exists()

    import importlib.util

    assert importlib.util.find_spec("tfpdf.genpack") is None
