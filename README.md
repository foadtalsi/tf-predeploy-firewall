# TF Pre-Deploy Firewall

GitHub Action that statically scans the Terraform files changed in a PR and
flags risk patterns typical of AI-generated code, before `terraform apply`
ever runs. No `terraform plan`, no cloud credentials, no state file.

Detects:
- **Unknown/hallucinated attributes** — arguments that don't exist in a curated AWS provider schema.
- **Tutorial-copy patterns** — hardcoded credentials, `0.0.0.0/0` CIDRs, placeholder names (`example`, `test`, `my-bucket`...).
- **ForceNew changes** — edits to attributes known to force destroy+recreate on stateful resources (RDS, EBS, ElastiCache...).
- **Missing `prevent_destroy`** — critical stateful resources without a `lifecycle { prevent_destroy = true }` guard.

## Usage

```yaml
name: tf-predeploy-firewall
on:
  pull_request:
    paths: ["**/*.tf"]

permissions:
  pull-requests: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: foadtalsi/tf-predeploy-firewall@v0
        with:
          block-threshold: high
```

`block-threshold` (`low|medium|high|critical`) sets the minimum severity
that fails the check; defaults to `high` via [config/default.yml](config/default.yml).

## Extending AWS coverage

All provider-specific knowledge lives in `internal/schema/data/*.json`:
- `aws_resource_schemas.json` — allowed attributes per resource type.
- `aws_forcenew_attrs.json` — ForceNew attributes per resource type.
- `critical_stateful_resources.json` — resource types requiring `prevent_destroy`.

Add entries there; no Go code changes needed.

## Local run

```sh
go run ./cmd/scanner --repo-dir . --base-ref origin/main --head-ref HEAD
```
