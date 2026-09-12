# Usage and configuration

[Back to README](../README.md)

## Choose a scan mode

Run from the repository root, or pass `--repo-dir /path/to/repository`.

| Mode | Files inspected | Compared contents |
|---|---|---|
| Default | Files changed between Git refs | `origin/main` → `HEAD` outside CI; the target branch in supported CI |
| `--staged` | Staged changes | `HEAD` → index |
| `--uncommitted` | Staged, unstaged, and untracked changes | `HEAD` → working tree |
| `--full-repo-scan` | All supported files | Current contents; no historical replacement comparison |

The last three options are mutually exclusive. Ref scans require the base revision
to exist locally. Local staged and uncommitted scans do not publish PR comments.

## Read the result

| Exit code | Meaning |
|---|---|
| `0` | No unaccepted finding reaches the blocking threshold |
| `1` | At least one unaccepted finding reaches the threshold |
| `2` | Invalid arguments, unreadable configuration, or another scan failure |

The default threshold is `high`. Severity order is `low`, `medium`, `high`, `critical`.
A baseline or hosted waiver accepts a finding without removing it from the report.
Suppression removes matching findings from the report entirely.

A hosted quota refusal skips recording the scan but does not suppress reports or
change the findings-based exit code. Hosted-service failures produce warnings and
retain available local coverage.

Output is terminal text on a TTY and Markdown otherwise. Override it with
`--format text` or `--format markdown`. `NO_COLOR` disables color without changing
the format. Additional files can be written during the same scan:

```sh
tf-predeploy-firewall --full-repo-scan \
  --sarif-output findings.sarif \
  --codequality-output gl-code-quality.json
```

SARIF can be uploaded to GitHub Code Scanning. GitLab can ingest the Code Quality
file as an `artifacts:reports:codequality` artifact. Posting GitLab MR comments uses
`TFPDF_GITLAB_TOKEN` (preferred) or `GITLAB_TOKEN`, with the GitLab CI context.

## Local configuration

The default path is `config/default.yml`, relative to the invocation directory.
Override it with `--config` or `SCANNER_CONFIG`. A missing file keeps the defaults;
a malformed file fails visibly. This repository's own config excludes intentionally
insecure test fixtures and is not a template you need to copy.

```yaml
block_threshold: high
suggestions: true
plan_blast_radius_threshold: 10
ignore_rules: []
ignore_paths:
  - path: "legacy/**"
    categories: [missing_lifecycle]
```

`ignore_rules` contains **category names**, listed in the [rule reference](rules.md).
An `ignore_paths` entry without categories suppresses every category under that path.
`**` matches across directory levels. To suppress one location, add the category on
that line or immediately above it:

```hcl
# tf-firewall-ignore: missing_lifecycle
resource "aws_s3_bucket" "temporary" {
  bucket = "example-temporary-storage"
}
```

Environment overrides include `SCANNER_BLOCK_THRESHOLD`,
`SCANNER_PLAN_BLAST_RADIUS_THRESHOLD`, and `SCANNER_SUGGESTIONS`. To request extra
GitHub reviewers on critical findings, configure `require_second_reviewer_users` or
`require_second_reviewer_teams`; mandatory approval is a branch-protection setting.

## Baselines

After reviewing existing findings, write and commit a baseline:

```sh
tf-predeploy-firewall --full-repo-scan --write-baseline .tf-firewall-baseline.json
```

Pass `--baseline .tf-firewall-baseline.json` to later scans, or set the Action's
`baseline` input. Matching uses rule name, category, resource, and file, not severity,
message, or line number. Review acceptances when the risk changes. Version 1 files
lack rule identity and match more broadly; regenerate them to use version 2.

## Custom rules

Simple organization-specific checks go in the local config:

```yaml
custom_rules:
  - id: no-iam-users
    resource_type: aws_iam_user
    severity: high
    message: "Use IAM roles instead of long-lived IAM users."
```

Preview them with `tf-predeploy-firewall --rules-dry-run`. This scans the whole
repository without posting comments or reporting usage. Matches do not fail the
command; invalid configuration still does. See [architecture](architecture.md) for
where custom rules enter the engine.

For a complete external rule pack, export `tf-predeploy-firewall --print-rules` to a
YAML file and load it with `--rules path/to/rules.yml`. It replaces built-ins unless
it declares `extends: builtin`. External packs are data, not executable Python.

## Pre-commit

Add this to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/foadtalsi/tf-predeploy-firewall
    rev: v1.2.4
    hooks:
      - id: tf-predeploy-firewall
```

The hook scans the Git index, including supported variable files. It can therefore
report different findings from a working-tree scan after selective staging.

## Optional plan input

Create a plan using your normal Terraform workflow, then export and scan it:

```sh
terraform show -json tfplan > plan.json
tf-predeploy-firewall --base-ref origin/main --plan-json plan.json
```

The scanner reads that file; it never runs Terraform itself. The plan adds confirmed
replacement, drift, and blast-radius checks. Plan files can contain sensitive values;
keep them within your normal plan-handling workflow.

## Hosted scan history

Set `TFPDF_LICENSE_KEY` to enable hosted reporting, waivers, and extended schema packs.
Repository identity resolves from `--repo-name` / `TFPDF_REPO_NAME`, CI variables,
then the Git remote. A missing identity produces a warning and skips reporting.

The reported scan initiator is the first nonempty value in `TFPDF_SCAN_ACTOR`,
`GITHUB_TRIGGERING_ACTOR`, `GITHUB_ACTOR`, or `GITLAB_USER_LOGIN`. Set
`TFPDF_SCAN_ACTOR` for local scans. This is reported metadata, not authenticated proof
of who authored the code. Paid dashboards can sort findings by date, user, and severity.

## Bedrock auto-fix: Growth only

This feature requires a CLI or Action revision containing auto-fix support and the
hosted `/v1/autofix` endpoint. Older `@v1` releases may not include it.

```sh
export TFPDF_LICENSE_KEY="your-api-key"
tf-predeploy-firewall --uncommitted --autofix
```

The server checks for an active Growth subscription. Enabling auto-fix sends affected
Terraform files and their unwaived findings to the hosted service for Bedrock processing.
There is one proposal per file. The CLI displays a diff and asks for confirmation;
without a terminal, it only previews. It does not stage or commit files, and it refuses
to overwrite source that changed after the proposal was prepared.

In the scanner's GitHub Action step:

```yaml
with:
  license-key: ${{ secrets.TFPDF_LICENSE_KEY }}
  autofix: "true"
```

Keep the checkout and permissions from the [README](../README.md). Review the proposed
code, then accept it through **Commit suggestion**. Suggestions outside the PR diff
remain in the summary for manual application. Fork PRs without the license secret
continue scanning without Bedrock fixes.

Failed, empty, malformed, or truncated responses leave files and verdicts unchanged;
existing deterministic suggestions remain available. The service limits requests to
64 KiB and generation to 2,048 tokens. After accepting a fix, review it, validate the
Terraform, and rerun the scan. Acceptance does not change the current scan's verdict.
