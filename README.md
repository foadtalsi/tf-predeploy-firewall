# TF Pre-Deploy Firewall

An open-source scanner that reviews Terraform changes before deployment. It detects
unknown provider arguments, replacement risks, hardcoded credentials, and unsafe
configuration, then reports the affected files and lines.

The core is **MIT-licensed** and runs locally without an account, Terraform, cloud
credentials, or a plan. It includes its parser, rules, provider schema packs, and
report renderers. GitHub comments, AWS lookups, and hosted features use network
access when enabled.

[Usage](docs/usage.md) · [Rules](docs/rules.md) · [Architecture](docs/architecture.md) ·
[Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Run your first scan

Requires Python 3.11 or later and Git. Install from this repository:

```sh
pip install git+https://github.com/foadtalsi/tf-predeploy-firewall@v1
cd /path/to/your/terraform-repository
tf-predeploy-firewall --full-repo-scan
```

A full scan checks existing files. To review a change instead:

```sh
# Compare two commits or branches. Fetch the base branch first.
tf-predeploy-firewall --base-ref origin/main --head-ref HEAD

# Review local edits, including untracked files.
tf-predeploy-firewall --uncommitted

# Review exactly what is staged for the next commit.
tf-predeploy-firewall --staged
```

The scanner also checks `terragrunt.hcl`, `.tfvars`, and `.tfvars.json` files.
Use `--help` for all options and `--format text` for a compact report in CI logs.

## GitHub Actions

Save this as `.github/workflows/terraform-review.yml`:

```yaml
name: Terraform review
on:
  pull_request:
    paths:
      - "**/*.tf"
      - "**/*.tfvars"
      - "**/*.tfvars.json"
      - "**/terragrunt.hcl"

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: foadtalsi/tf-predeploy-firewall@v1
```

The full checkout makes the base revision available. The action creates or updates
a summary comment and posts exact fixes as review suggestions. Review a suggestion
before accepting it with **Commit suggestion**. Repository branch protection controls
whether a failed scan prevents merging.

These docs describe the current source. Installation examples use `@v1`; newer
features such as Bedrock auto-fix require a release or commit containing them.
See [the Action inputs](action.yml) and [usage guide](docs/usage.md).

## What it checks

| Check | Example |
|---|---|
| Unknown arguments | An attribute absent from the loaded provider schema |
| Replacement risks | A changed `ForceNew` attribute on an existing resource |
| Credentials | Hardcoded passwords, known token formats, high-entropy secrets |
| Destruction guards | Missing `prevent_destroy`, S3 `force_destroy = true` |
| Version constraints | Unpinned modules or providers |
| Unsafe configuration | Public access, disabled encryption, broad IAM permissions |
| Optional plan checks | Confirmed replacement, unexplained drift, large blast radius |

The [rule reference](docs/rules.md) explains each category and suggested remediation.
Severity is ordered **low → medium → high → critical**. By default, an unaccepted
finding at **high** or **critical** makes the scan fail.

Static analysis has limits. Unresolved expressions are not guessed. Schema checks
cover the resource types in the loaded packs. If a module's provider constraint
excludes the loaded schema version, the scanner warns and skips unknown-attribute
and ForceNew findings for that provider; other checks still run. It does not fetch
an older matching schema or replace `terraform validate` and plan review.

## Adopt it on an existing repository

Review the initial findings, then record accepted existing risks:

```sh
tf-predeploy-firewall --full-repo-scan --write-baseline .tf-firewall-baseline.json
tf-predeploy-firewall --full-repo-scan --baseline .tf-firewall-baseline.json
```

Commit the baseline and pass it in subsequent scans. Accepted findings remain
visible without blocking; new findings still count. Entries match rule, category,
resource, and file, so moving a line does not invalidate them.

For narrower exclusions, configuration, reports, and pre-commit setup, read the
[usage guide](docs/usage.md).

## Optional integrations

The local scanner works independently of the hosted service. A license key enables
extended provider coverage, scan history, and dashboard waivers. Bedrock-generated
fixes require explicit opt-in and an active **Growth** plan; users accept the proposed
code in the CLI or GitHub. The cloud backend is a separate project.

[AWS read-only access](docs/cloud-read-access.md) is independent of paid plans. It
can adjust S3 findings using bucket existence and contents metadata without reading
object contents. Neither integration is required to run or contribute to the core.

## Read and contribute to the code

Start with the [architecture guide](docs/architecture.md) to follow a scan from Git
changes to findings. [CONTRIBUTING.md](CONTRIBUTING.md) covers local setup, tests, rule
changes, and generated documentation.

## License

[MIT](LICENSE).
