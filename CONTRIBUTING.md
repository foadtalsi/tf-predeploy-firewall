# Contributing

You can develop and test the core without a cloud account, license key, or access to
the hosted backend. Start with the [architecture guide](docs/architecture.md) if you
want to follow the code before making a change.

## Set up locally

Requirements: Git and Python 3.11–3.13, the versions tested in CI.

```sh
git clone https://github.com/foadtalsi/tf-predeploy-firewall.git
cd tf-predeploy-firewall
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
tf-predeploy-firewall --help
```

The editable install uses your source changes immediately. Tests use temporary Git
repositories, loopback HTTP servers, and mocked AWS calls. They do not require live
cloud credentials. Your environment must allow local loopback servers.

## Check a change

Run the relevant test file while developing, then the CI checks before submitting:

```sh
ruff check src tests
ruff format --check src tests
mypy
pytest
```

Use `ruff format src tests` to apply formatting. For example, run
`pytest tests/test_engine.py` after changing engine behavior. Include a regression
case for the bug you fix, with a minimal Terraform example and expected finding.

## Change a rule

1. Read the relevant entry in `src/tfpdf/ruledef/rules.py` and its explanation in
   [docs/rules.md](docs/rules.md).
2. Change the declarative definition or the specialized detector under
   `src/tfpdf/rules/`. Keep rule IDs stable: baselines and integrations depend on them.
3. Test both a risky example and a similar safe example. For exact fixes, check the
   replacement text and source range, including indentation.
4. Update the category help beside the rule, then regenerate its reference:

   ```sh
   pytest tests/test_report_parity.py --update-docs
   ```

5. Review the generated diff and rerun tests without `--update-docs`.

`docs/rules.md` is generated; edit its source definitions rather than the Markdown.
Files under `tests/data/` include frozen historical Go outputs. Do not regenerate
expected results from the implementation under test simply to make a failure pass.
Document intentional behavior changes and independently verify new expectations.

## Optional historical Go parity checks

Most tests run without Go. End-to-end CLI parity additionally needs Go 1.23 and a
binary from the historical revision used in CI. From an activated Python environment:

```sh
version=$(python -c 'import importlib.metadata as m; print(m.version("tf-predeploy-firewall"))')
go install -ldflags "-X main.version=$version" \
  github.com/foadtalsi/tf-predeploy-firewall/cmd/tf-predeploy-firewall@cf0bdd32d03866e3db023bd8223f848bfe89af8f
TFPDF_GO_BINARY="$(go env GOPATH)/bin/tf-predeploy-firewall" \
  pytest tests/test_cli_parity.py
```

Matching the version avoids unrelated SARIF differences. The test requiring the old
neighboring Go checkout still skips when that checkout is absent. The exact CI
commands live in [.github/workflows/ci.yml](.github/workflows/ci.yml).

The separate ForceNew extractor is Go tooling, not the scanner runtime. If you edit
it, run `gofmt`, `go vet ./...`, and `go test ./...` from
`tools/forcenew-extractor`.

## Keep changes readable

Write documentation, comments, and docstrings in English. Describe what a function
returns, its side effects, or an important assumption; do not repeat its name in a
paragraph. Put long explanations in a guide and keep useful context near the code.
Prefer direct code and clear names over unnecessary wrappers or abstractions.

A pull request should explain the problem, resulting behavior, and checks run. For
false positives, include a small reproducible configuration, scanner version, and
provider constraint. Use synthetic credentials in examples and test fixtures.
