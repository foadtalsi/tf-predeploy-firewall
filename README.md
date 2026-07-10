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
