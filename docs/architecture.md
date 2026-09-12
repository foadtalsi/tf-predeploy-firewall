# How the scanner works

[Back to README](../README.md) · [Development setup](../CONTRIBUTING.md)

The core is a Python package named `tfpdf`. The installed command
`tf-predeploy-firewall` calls `tfpdf.cli.main.run`. The GitHub Action starts the same
command in a container; it does not use a separate scanning engine.

## Follow one scan

1. **Read options.** `cli/arguments.py` declares flags. `cli/config.py` loads local
   YAML and environment overrides. `cli/main.py` validates the requested mode.
2. **Collect files.** `cli/terraformscan.py` selects the mode; `diff/` reads Git refs,
   the index, or the working tree. Each changed Terraform file carries base and head
   contents, so replacement checks can compare them.
3. **Load coverage and rules.** `schema/loader.py` reads embedded provider packs.
   `rules/pack.py` connects built-in definitions to detectors. A license can add
   extended schemas; local YAML can supply custom rules.
4. **Parse and inspect.** `rules/engine.py` builds directory scopes, parses files,
   runs detectors, and applies exclusions. Optional plan checks add findings and
   replace duplicate static replacement warnings. AWS opt-in can adjust eligible
   S3 findings.
5. **Apply acceptances.** `baseline.py` and `cli/orgpolicy.py` mark accepted findings.
   `cli/pipeline.py` compares the remaining severities with the blocking threshold.
6. **Publish.** `report/` renders findings. `cli/forges.py` handles PR/MR publication.
   Licensed scans may report usage; explicit auto-fix requests produce proposals
   for human review. Accepting a proposal does not alter the current verdict.

Read `cli/pipeline.py:execute_scan` first, then `_collect_findings` and
`rules/engine.py:run` for the main path.

## Find the code you need

Paths below are relative to `src/tfpdf/`.

| Area | Responsibility |
|---|---|
| `cli/` | Command options, scan orchestration, and integrations |
| `diff/` | File selection and before/after contents |
| `hcl/` | Tokens, syntax tree, source ranges, and limited static evaluation |
| `parser/` | Convert HCL into resources, attributes, and directory scopes |
| `ruledef/` | Rule format, built-in definitions, validation, and documentation |
| `rules/` | Engine, declarative matching, specialized detectors, and exact fixes |
| `schema/` | Embedded provider schemas, ForceNew metadata, and overlays |
| `report/` | Finding model, terminal, Markdown, SARIF, and Code Quality output |
| `baseline.py`, `ignore.py` | Accepted existing findings and suppression |
| `planjson.py` | Optional Terraform plan JSON input |
| `terragrunt.py`, `tfvars.py` | Checks for configuration outside resource blocks |
| `licensing/` | Optional hosted usage, waivers, and extended-pack delivery |
| `cloudread.py` | Optional AWS session and read-only operation guard |

`tools/forcenew-extractor/` contains separate Go tooling for extracting replacement
metadata from provider source. It is not invoked during a scan.

## Understand the main types

`diff.ChangedFile` holds a path and its base/head contents. The parser converts HCL
blocks into `parser.Resource` objects with normalized attributes and source ranges.
A detector receives `rules.FileInput` and returns `report.Finding` objects.

A finding carries a rule ID, category, severity, location, resource address, and
explanation. A category can contain several rules: `missing_lifecycle` and
`s3_force_destroy`, for example, must remain distinct in baseline matching.
An optional `report.Fix` replaces an inclusive, one-based line range. If a reliable
replacement cannot be built, the finding can still contain textual advice.

## Preserve these contracts

- **Unknown is not null.** Expressions requiring Terraform execution stay unknown.
  Rules must not treat unresolved references as literal values. Function calls are
  deliberately not evaluated; some detectors inspect their raw source instead.
- **Locations belong to the original source.** Ranges use UTF-8 byte offsets and
  one-based lines/columns. Review comments and exact fixes depend on them.
- **Scope is per module directory.** Locals and variable defaults in sibling files
  can resolve, but scopes do not cross directory boundaries. Supplied scan contents
  take precedence over disk contents.
- **Schema coverage is explicit.** Unsupported types or incompatible provider
  versions cannot support schema claims. Value-based checks still run.
- **Accepted and suppressed are different.** Accepted findings remain visible and
  do not block. Suppressed findings are removed from the report.
- **Rules are data at the external boundary.** YAML selects known predicates and
  fix actions; it cannot import arbitrary Python.

## Optional network boundaries

The default local scan uses embedded data. Code-host publication calls GitHub or
GitLab. A license key enables hosted scan metadata, waivers, and pack downloads;
auto-fix additionally sends affected Terraform source when explicitly requested.
The Bedrock Lambda and subscription checks live in the separate cloud backend.

AWS read access is a separate opt-in. Its allowlist permits only STS identity and
S3 object listing; [the AWS guide](cloud-read-access.md) explains setup and failure
behavior. Network failures in optional services do not discard the local report.

## Tests as examples

`tests/test_engine.py` shows how to scan a change directly. `tests/test_field_reports.py`
contains real-world false-positive regressions. `tests/test_cli_integration.py`
exercises the installed command on temporary repositories. Parser and report parity
tests use frozen Go outputs to protect source ranges and machine-readable formats.
