# TF Pre-Deploy Firewall

Terraform review on every pull request. Free, MIT-licensed, no account.

It reads the Terraform changed in a pull request against the provider's real
schema and comments on the line that caused the finding. No `terraform init`,
no plan, no state file, no credentials, no network call. Unlimited
repositories, unlimited scans.

[tfpredeployfirewall.com](https://tfpredeployfirewall.com) · [Rules reference](docs/rules.md) · [Changelog](CHANGELOG.md)

---

## The problem it exists for

An agent asked to rename a database and turn on deletion protection produced
exactly this:

```hcl
resource "aws_db_instance" "primary" {
  identifier     = "prod-primary"
- db_name        = "appdb"
+ db_name        = "app_production"
  ...
+ enable_deletion_protection = true
}
```

Both lines are wrong, and neither is wrong in a way that reads wrong.

`db_name` is ForceNew on `aws_db_instance` — changing it destroys and recreates
the database. `enable_deletion_protection` is not an argument of that resource
at all; the real one is `deletion_protection`, so the guard the pull request
claims to add does not exist. A reviewer sees a rename and a safety flag. The
plan sees a destroy.

## Install

Both paths run the same engine on the same 34 rules. Pick whichever you already
have.

### GitHub Actions

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
        with: { fetch-depth: 0 }
      - uses: foadtalsi/tf-predeploy-firewall@v1
```

That is the whole file — no key, no secret, no `with:` block. `fetch-depth: 0`
matters: without it the runner has no base branch to diff against.

### CLI

```console
$ pip install \
  git+https://github.com/foadtalsi/tf-predeploy-firewall@v1

$ cd infra/terraform
$ tf-predeploy-firewall --full-repo-scan
```

### pre-commit

```yaml
repos:
  - repo: https://github.com/foadtalsi/tf-predeploy-firewall
    rev: v1.2.4
    hooks:
      - id: tf-predeploy-firewall
```

This one scans the git index, so a secret is caught while removing it is still
an edit rather than a rotation.

## What it checks

Thirteen categories, 34 rules. The full reference — what each detects, why it
interrupts a merge, and how to disagree with it — is in
[`docs/rules.md`](docs/rules.md).

| | |
|---|---|
| **Hallucinated arguments** | Arguments the provider does not declare, checked against a generated schema rather than a hand-written list |
| **Destroy+recreate traps** | ForceNew attributes whose value the pull request changes |
| **Credentials in source** | Known key formats, plus a calibrated entropy fallback for the ones with no format |
| **Missing guards** | Stateful resources with no `prevent_destroy`, `force_destroy` on buckets |
| **Unpinned versions** | Module sources and providers with no version constraint |
| **Open exposure** | `0.0.0.0/0` ingress, public buckets, disabled encryption, wildcard IAM |

It also reads `terragrunt.hcl`, `.tfvars` and `.tfvars.json` — a secret moved
out of `main.tf` has to land somewhere.

## What it does not do

This list is the product, not a disclaimer.

- **It never runs `terraform`.** No `init`, no `plan`, no provider download.
- **It reads no state.** Your state file is where your secrets are.
- **It needs no credentials.** Nothing to grant, nothing to rotate, nothing to
  leak from a CI runner.
- **It makes no network call**, unless you hand it a license key.
- **It never fails your build because of us.** A finding fails the build; an
  error on our side does not.

## It judges against the provider you pinned

This is the difference between this scanner and `terraform validate`.

A repository that declares `aws = "~> 3.0"` legitimately writes `vpc = true` on
an `aws_eip` — the attribute only disappeared in 6.x. The scanner reads the
`required_providers` constraint from the module's directory, and when the
schema it carries falls outside the pinned range it drops the two
schema-derived rules for that provider and says so:

```
aws is pinned to "~> 3.0" here, and the schema this scanner carries is 6.59.0.
Attribute and ForceNew findings for aws were dropped rather than judged against
a version you do not use — every other rule still ran.
```

Silence beats a confident wrong answer: we do not hold that version's schema,
so we have nothing to say about its arguments. Every rule that judges a written
value — credentials, entropy, open CIDRs, missing guards — still runs. A
hardcoded password is a hardcoded password on every version of AWS.

## Pointing it at a repository that already exists

It will find a lot. That is usually where these tools die, so there are four
levels of suppression, narrowest first:

| Scope | How |
|---|---|
| One line | `# tf-firewall-ignore: <category>` above or on the line |
| One path | `ignore_paths:` in the config file, optionally scoped to categories |
| One category, everywhere | `ignore_rules:` in the same file |
| Everything that exists today | a committed baseline |

The baseline is the one that matters on adoption day:

```console
$ tf-predeploy-firewall --full-repo-scan --write-baseline .tf-firewall-baseline.json
$ git add .tf-firewall-baseline.json
```

Commit it and pass `--baseline`. Everything in it stays visible in the pull
request comment and stops blocking; anything new blocks. Entries match on
rule + category + resource + file, never on line number — a baseline that
breaks when you add a line above would be worse than none.

The config file is read from `config/default.yml` by default, overridable with
`--config` or `SCANNER_CONFIG`.

## Optional extras

Each is off unless you ask for it.

| Flag | What it adds |
|---|---|
| `--plan-json <file>` | Reads the output of `terraform show -json` that **you** produced, with your own credentials, to add confirmed-replace, drift and blast-radius findings. This tool never runs terraform. |
| `--cloud-read-access` | Uses the job's existing credentials to read whether the resources a finding is about already exist and how much they hold, so severity reflects the real account. Read-only and narrowly so — see [`docs/cloud-read-access.md`](docs/cloud-read-access.md). |
| `--sarif-output <file>` | SARIF 2.1.0 for GitHub Code Scanning. |
| `--codequality-output <file>` | GitLab Code Quality report, rendered in the merge request widget with no token. |
| `--license-key` | A paid plan: the full 2,840-type provider knowledge base, the dashboard, central policy, waivers, history. |

## Exit codes

| | |
|---|---|
| `0` | No finding at or above the blocking threshold |
| `1` | Blocked — something reached the threshold |
| `2` | The scanner could not run (bad flag, unreadable config, unreachable git ref) |
| `3` | A license key was given and its plan's quota is exhausted |

## Free and paid

The scanner is MIT and stays that way. It carries embedded packs covering 80
AWS and Azure resource types — the ones most repositories use most, generated
from `terraform providers schema -json` rather than curated by hand.

A plan swaps them for all 2,840 types across both providers, and adds the
operational half: dashboard, centrally-managed policy, per-finding waivers with
a written justification, history, SSO. Most repositories never need it, and we
would rather you find that out than be told it.

Nothing you install today stops working if you never buy a plan.

## Licence

MIT. See [LICENSE](LICENSE).

### Scan history attribution

Paid dashboards provide a Findings page with date, user and severity sorting.
Usage reports attach the scan initiator from `TFPDF_SCAN_ACTOR`, then
`GITHUB_TRIGGERING_ACTOR`, `GITHUB_ACTOR`, or `GITLAB_USER_LOGIN` (first non-empty
value). For local scans, set `TFPDF_SCAN_ACTOR` explicitly. This is a reported
identity, not verified dashboard authentication or the author of the affected code.
Older scans without this field display “Not recorded”. Reporting still requires
`TFPDF_LICENSE_KEY` and a repository identity.
