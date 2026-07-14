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

## Inputs

| Input | Default | Description |
|---|---|---|
| `base-ref` | PR base branch | Git ref to diff against. |
| `block-threshold` | `high` (from config) | Minimum severity (`low\|medium\|high\|critical`) that fails the check. |
| `github-token` | `github.token` | Token used to post/update the PR comment. |
| `sarif-output` | _(empty, disabled)_ | Path to write a SARIF 2.1.0 file, for upload to GitHub Code Scanning via `github/codeql-action/upload-sarif` — gives inline PR annotations on the exact changed lines, see example below. |
| `plan-json` | _(empty, phase 1 only)_ | Path to `terraform show -json <planfile>` output — see [Phase 2](#phase-2-analyzing-a-real-terraform-plan-optional) below. |
| `plan-blast-radius-threshold` | `10` (from config) | Number of destroy/replace actions in the plan that triggers a large-blast-radius finding. Only used with `plan-json`. |
| `license-key` | _(empty, free tool)_ | Optional paid-plan API key — see [Paid plans](#paid-plans-optional) below. |

### SARIF / GitHub Code Scanning

```yaml
      - uses: foadtalsi/tf-predeploy-firewall@v0
        with:
          block-threshold: high
          sarif-output: tf-firewall.sarif

      - uses: github/codeql-action/upload-sarif@v3
        if: always()  # upload findings even when the scan step fails (blocked PR)
        with:
          sarif_file: tf-firewall.sarif
```

This requires `security-events: write` in the workflow's `permissions:` block.

## Phase 2: analyzing a real `terraform plan` (optional)

Phase 1 above is a pure static scan — no cloud credentials, no state. If your
pipeline already runs `terraform plan` with real credentials elsewhere, you
can feed its output to this action for three additional checks that a static
diff can't make:

- **Confirmed replace** — Terraform's own plan, not a heuristic, says a
  stateful/critical resource will be destroyed or destroyed+recreated.
- **Unexpected drift** — a sensitive attribute is changing in the plan even
  though this PR's `.tf` diff never touched it (state drift, a provider
  default shifting, an out-of-band edit).
- **Large blast radius** — the plan destroys/replaces more resources than
  `plan_blast_radius_threshold` (default 10) — a sign of an unintended module
  move or provider upgrade side-effect.

This action never runs `terraform` or touches your cloud provider. You run
`terraform plan` yourself, convert it to JSON, and pass the path:

```yaml
      - run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > plan.json
        # ... your own AWS/cloud credentials go here, not this action's

      - uses: foadtalsi/tf-predeploy-firewall@v0
        with:
          block-threshold: high
          plan-json: plan.json
```

Leave `plan-json` empty (the default) to run phase 1 only.

## Paid plans (optional)

This action is, and always will be, fully usable for free with zero external
dependency — nothing above requires an account or a network call outside
GitHub. A paid plan (Starter/Growth/Scale — see
[tfpredeployfirewall.com](https://tfpredeployfirewall.com)) only exists for
teams that want usage tracking across many repos, centralized policy
management, or an SLA; it adds nothing to what the free tier detects.

```yaml
      - uses: foadtalsi/tf-predeploy-firewall@v0
        with:
          block-threshold: high
          license-key: ${{ secrets.TFPDF_LICENSE_KEY }}
```

Setting `license-key` reports each scan's outcome (repo name, finding
count, whether it blocked) to the billing service, which enforces your
plan's repo/scan limits. If that service is unreachable, the scan **still
runs** — a billing outage on our end is never the reason your PR check goes
red. Leave `license-key` unset (the default) to skip this entirely.

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
