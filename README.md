# TF Pre-Deploy Firewall

[![Scanned by TF Pre-Deploy Firewall](https://img.shields.io/badge/scanned%20by-TF%20Pre--Deploy%20Firewall-7c6cf0)](https://github.com/foadtalsi/tf-predeploy-firewall)

GitHub Action that statically scans the Terraform files changed in a PR and
flags risk patterns typical of AI-generated code, before `terraform apply`
ever runs. No `terraform plan`, no cloud credentials, no state file.

Detects:
- **Unknown/hallucinated attributes** — arguments that don't exist in a curated AWS provider schema.
- **Tutorial-copy patterns** — hardcoded credentials, `0.0.0.0/0` CIDRs, placeholder names (`example`, `test`, `my-bucket`...). Also applied to Terragrunt's `inputs`/`remote_state.config` maps in `terragrunt.hcl` (see below), not just `.tf` resource attributes.
- **ForceNew changes** — edits to attributes known to force destroy+recreate on stateful resources (RDS, EBS, ElastiCache...).
- **Missing `prevent_destroy`** — critical stateful resources without a `lifecycle { prevent_destroy = true }` guard.

### Terragrunt

If the repo uses Terragrunt, every changed `terragrunt.hcl` file's `inputs`
and `remote_state.config` maps (recursively, including nested maps) are
scanned for hardcoded credentials and open CIDRs — the same patterns
above, just applied to a config file that isn't `.tf` and isn't a resource
block. A value that references a local/dependency output (e.g.
`dependency.rds.outputs.password`) can't be evaluated statically and is
skipped, same as any other non-literal value elsewhere in this tool.

For hardcoded credentials and missing `prevent_destroy` guards, the PR comment
includes a **suggested fix**: a pasteable HCL snippet (e.g. the `lifecycle`
block to add, or a `variable` block to replace a hardcoded secret with).
It's a snippet to copy, not a computed patch — this tool never has write
access to your repo.

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

### Badge

Advertise that a repo is covered — copy this into its README:

```markdown
[![Scanned by TF Pre-Deploy Firewall](https://img.shields.io/badge/scanned%20by-TF%20Pre--Deploy%20Firewall-7c6cf0)](https://github.com/foadtalsi/tf-predeploy-firewall)
```

This is a static badge (via [shields.io](https://shields.io)'s static-badge
endpoint) — it doesn't reflect this specific repo's latest scan result, and
never phones home to anything this project runs. It's a marker of coverage,
not a live status.

### Making this a required check

Detecting risk patterns only stops a bad merge if the check can't be
skipped. To make it a hard gate on a branch:

1. Add the workflow above to `.github/workflows/` — the job is named
   `scan` under the workflow name `tf-predeploy-firewall`, so it shows up
   in GitHub as the check **`tf-predeploy-firewall / scan`**. Keep the job
   name as `scan` (or update the steps below to match if you rename it) —
   branch protection references it by this exact name.
2. In the repo's **Settings → Branches → Branch protection rules**, add or
   edit a rule for the branch PRs merge into (usually `main`).
3. Enable **"Require status checks to pass before merging"**, then search
   for and select **`tf-predeploy-firewall / scan`**.
4. Optionally also enable **"Require branches to be up to date before
   merging"** so the check always runs against the latest base.

Once required, a PR with a blocked finding physically can't be merged from
the GitHub UI, regardless of who approves it — this is what turns a
scanner into an actual gate rather than an FYI comment.

## Inputs

| Input | Default | Description |
|---|---|---|
| `base-ref` | PR base branch | Git ref to diff against. |
| `block-threshold` | `high` (from config) | Minimum severity (`low\|medium\|high\|critical`) that fails the check. |
| `github-token` | `github.token` | Token used to post/update the PR comment. |
| `sarif-output` | _(empty, disabled)_ | Path to write a SARIF 2.1.0 file, for upload to GitHub Code Scanning via `github/codeql-action/upload-sarif` — gives inline PR annotations on the exact changed lines, see example below. |
| `plan-json` | _(empty, phase 1 only)_ | Path to `terraform show -json <planfile>` output — see [Phase 2](#phase-2-analyzing-a-real-terraform-plan-optional) below. |
| `plan-blast-radius-threshold` | `10` (from config) | Number of destroy/replace actions in the plan that triggers a large-blast-radius finding. Only used with `plan-json`. |
| `cost-impact-threshold-usd` | `0`, disabled (from config) | Estimated monthly USD cost increase that triggers a cost-impact finding. Only used with `plan-json`. |
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
- **Cost impact** — the plan's estimated monthly AWS bill increase (from a
  curated, region-agnostic pricing table) crosses `cost_impact_threshold_usd`
  (default 0, disabled). This is a rough on-demand estimate meant as an
  early-warning signal in review — not a billing-accurate quote. Resource
  types not in the pricing table contribute $0 rather than being guessed at.

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

## Scheduled drift audit

`--full-repo-scan` scans every `.tf` file in the repo instead of just a PR
diff — for a cron-triggered audit of code that's already merged, not a PR
check. Detection rules that compare before/after (ForceNew) naturally find
nothing, since there's no diff; rules that check current content on its
own (unknown attributes, tutorial patterns, missing `prevent_destroy`) run
at full strength. This catches drift between what a repo's rule/schema
coverage was when it merged and what it is now — Terraform that was clean
last month can fail today purely because this tool's detection grew, with
zero code changes to explain it. See
[.github/workflows/scheduled-drift-audit.yml](.github/workflows/scheduled-drift-audit.yml)
for a complete example (weekly cron + manual dispatch, SARIF upload, no PR
comment since there's no PR).

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

### Waivers (Starter+)

Accept a specific finding — a known false positive, or a risk your team has
consciously decided to live with — without lowering `block-threshold` for
everything else. Configured in the dashboard (`/waivers`), matched by
category + resource + file within a repo (not by line, so an unrelated edit
above it doesn't silently un-waive it). A waiver never disappears from the
PR comment: it moves to a separate, collapsed "waived findings" section
with its justification, so accepting a finding is a documented decision,
not a silent removal. Set an optional expiry to force the team to revisit
it instead of it becoming permanent by accident.

## Custom rules (policy-as-code)

Beyond the built-in checks, define your own detection rules declaratively in
`config/default.yml` (or wherever `--config` points):

```yaml
custom_rules:
  - id: no-iam-users
    resource_type: aws_iam_user
    severity: medium
    message: "Use aws_iam_role instead of aws_iam_user"

  - id: no-public-acl
    resource_type: aws_s3_bucket
    attribute: acl
    pattern: "public"
    severity: high
    message: "S3 bucket ACL must not be public"

  - id: require-env-tag
    resource_type: aws_instance
    attribute: environment_tag
    pattern: ".+"
    negate: true       # fires when the pattern does NOT match, or the attribute is absent
    severity: low
    message: "aws_instance must set environment_tag"

  - id: no-wide-open-ingress
    resource_type: "*"
    block: ingress     # match inside a nested block instead of the resource's top level
    attribute: cidr_blocks
    pattern: "0\\.0\\.0\\.0/0"
    severity: critical
    message: "ingress block allows 0.0.0.0/0"
```

Each rule matches a `resource_type` (or `*` for any), optionally scoped to a
nested `block`, and optionally checks one `attribute`'s literal value
against a regex `pattern`. Omitting both `attribute` and `pattern` just
flags the resource/block's presence. `negate: true` inverts the match —
useful for "this must be present and look like X" rules.

**This is a declarative DSL, not a scripting language** — there's no
eval/exec surface, deliberately. This tool runs inside other people's CI
pipelines; letting an org's config execute arbitrary code here would be a
supply-chain risk this project isn't willing to take on for a convenience
feature. If a rule needs more than "does this attribute match this regex,"
it belongs in a fork or an upstream feature request, not in this file.

Findings from custom rules appear in the PR comment and SARIF output
under category `custom:<rule id>`.

## Ignoring entire paths

Beyond an inline `# tf-firewall-ignore:` comment (one line) and
`ignore_rules` (one category everywhere), `ignore_paths` suppresses
findings under a whole file/directory glob — for a legacy or sandbox tree
you've deliberately decided not to enforce on, without littering every file
in it with comments:

```yaml
ignore_paths:
  - path: "legacy/**"          # every category, anywhere under legacy/
  - path: "sandbox/*.tf"       # single "*" doesn't cross a "/"
    categories: [missing_lifecycle]  # optional; omitted = every category
```

`**` matches any number of path segments (including zero); `*` and `?`
behave as usual within one segment. For a single specific finding rather
than a whole path, see [Waivers (Starter+)](#waivers-starter) below instead.

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
