# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed
- **Provider knowledge is now generated, not hand-curated.** All of it lives
  in *rule packs* built by the new `cmd/genpack` from two authoritative
  sources: `terraform providers schema -json` for the argument surface, and
  the AWS provider's own Go source for the ForceNew flags that schema
  doesn't expose (SDKv2 `ForceNew: true` and Framework `RequiresReplace()`,
  1234/1234 and 452/459 resources resolved respectively).

  Coverage went from 33 hand-listed resource types to **1,699**, and from 18
  types with ForceNew data to **1,485**. Nesting is now handled at any depth
  via dotted block paths, not just one level.

  This fixes wrong data in both directions:
  - The curated schema listed **29 arguments for `aws_instance`**; the
    provider declares **71**. Every omission (`launch_template`,
    `cpu_options`, `hibernation`, `network_interface`, …) was reported as a
    hallucinated attribute at severity `high` — a blocked PR on valid
    Terraform. This was the single largest source of false positives.
  - `identifier` was listed as ForceNew on `aws_db_instance`. It isn't: the
    provider renames in place. The scanner was warning that a rename would
    destroy a production database.

  `schema.AWS`'s map fields are replaced by accessors (`ResourceSchema`,
  `ForceNew`, `IsCritical`, `PricingFor`) so entries decode lazily — the full
  pack is ~14 MB of JSON and a scan touches a few dozen types.

- **Open-core split.** The scanner, every rule, and the free base pack (39
  common AWS types) stay MIT-licensed and work with no account and no network
  call. The extended pack (all 1,699 types) is fetched with a license key.
  Both packs are cut from the same generated data, so they can never disagree
  about a type they share.

### Added
- **Extended rule pack delivery** — `GET /v1/rulepacks/aws`, cached on the
  runner for 24h and revalidated with an ETag (steady state: a 304, no body).
  Fails soft in every direction: control plane unreachable → cached pack;
  no cache → the embedded base pack; corrupt pack → base pack. Each case
  warns on stderr rather than silently scanning with less coverage, and none
  of them can fail a scan. `TFPDF_CACHE_DIR` points the cache at a directory
  CI already restores.
- Every scan now logs which packs it loaded, the provider version they
  describe, and how many resource types they cover — so "why didn't it catch
  this?" has an answer.
- **Per-finding waivers (Starter+)** — an admin accepts a specific finding
  (matched by category + resource + file, not by line — line drifts on
  unrelated edits) from the dashboard instead of lowering `block_threshold`
  for everything else. Fetched once per scan (`GET /v1/waivers`, fails open
  if unreachable). A waived finding never disappears from the PR
  comment — it moves to a separate, collapsed section with its
  justification — and is excluded from SARIF output and the block decision.
- **Scheduled drift audit (`--full-repo-scan`)** — scans every `.tf` file
  currently in the repo, not just a PR's diff, for a cron-triggered job
  against the default branch. Catches Terraform that was clean when it
  merged but no longer is because the scanner's own rule/schema coverage
  grew since then. ForceNew-change detection naturally finds nothing
  (there's no diff to compare against); unknown-attribute, tutorial-pattern,
  and missing-lifecycle findings run at full strength against current
  content.
- **Terragrunt support** — `terragrunt.hcl` files' `inputs` and
  `remote_state.config` maps (recursively, including nested maps) are now
  scanned for the same hardcoded-credential and open-CIDR patterns
  `TutorialPatternRule` already applies inside `.tf` resource blocks.
  Previously invisible to the scanner entirely, since it only ever
  considered `*.tf` files — a real gap for Terragrunt users, since
  `inputs` commonly carries exactly the kind of secret this tool exists to
  catch. Picked up by both the PR-diff scan and `--full-repo-scan`.
- **Per-repo policy overrides** — `GetPolicy` accepts the scanning repo's
  full name and merges a repo-specific override on top of the org-wide
  policy, per field, so one repo can tighten (or loosen) just its block
  threshold without restating the whole policy.
- **Finding detail reporting** — usage reporting (`--license-key`) now
  sends each finding's category, severity, resource, file/line, and
  message, not just a bare count — the paid dashboard's Reports/Trends/
  Audit Log can finally show what was actually found, not just a number.
- Badge (static, shields.io) and step-by-step required-status-check
  instructions in the README — turning this from an FYI comment into an
  actual merge gate, and a lightweight organic-growth lever for public repos.

## [v0] — current

### Added
- **Phase 1: static scan** — no cloud credentials, no `terraform plan`, no state.
  Detects, on the `.tf` files changed in a PR:
  - Unknown/hallucinated attributes (curated AWS provider schema, 27 resource types).
  - Tutorial-copy patterns: hardcoded credentials (by attribute name *and* by value
    pattern — AWS keys, PEM keys, JWTs, GitHub tokens), `0.0.0.0/0` CIDRs (including
    inside `ingress`/`egress` nested blocks), generic placeholder names.
  - ForceNew attribute changes (top-level and nested-block) on pre-existing resources.
  - Missing `lifecycle { prevent_destroy = true }` on stateful/critical resources.
  - Suggested fixes: a pasteable HCL snippet in the PR comment for missing-lifecycle
    and hardcoded-credential findings (a suggestion, not a computed file patch —
    this tool never has write access to the repo).
- **Custom rules (policy-as-code)** — declarative YAML rules (`custom_rules` in
  config): resource type + optional nested block + optional attribute/regex match.
  No eval/exec surface by design — this tool runs inside other people's CI, so
  letting org config execute arbitrary code was never on the table. Findings
  appear under category `custom:<id>`.
- **Phase 2: `terraform plan` analysis (optional, `--plan-json`)** — still no cloud
  credentials or terraform execution in this tool; reads a plan the user already
  generated in their own job.
  - Confirmed destroy/replace, straight from the plan's own diff engine.
  - Unexpected drift: a sensitive attribute changes in the plan but wasn't touched
    by the PR's own `.tf` diff.
  - Large blast radius: too many destroy/replace actions in one plan (configurable
    threshold).
  - Cost impact: estimated monthly AWS bill increase from a curated, region-agnostic
    pricing table (configurable threshold, disabled by default) — an early-warning
    FinOps signal, not a billing-accurate quote.
  - Phase 1's ForceNew heuristic is deduplicated against phase 2's confirmed replace
    for the same resource, so a real plan doesn't produce two findings for one problem.
- Two-tier suppression: inline `# tf-firewall-ignore: <category>` comments, and a
  global `ignore_rules` list in `config/default.yml`.
- SARIF 2.1.0 output (`--sarif-output`) for GitHub Code Scanning inline PR annotations.
- PR comment is upserted (edited in place on re-runs), not reposted every push.
- Configurable severity gate (`block_threshold`, default `high`) via config file,
  env var, or GitHub Action input.
- Docker-based GitHub Action (`action.yml` + `Dockerfile`), ~51 MB image.
- Curated AWS knowledge lives entirely in `internal/schema/data/*.json` — extending
  coverage never requires a Go code change.

### Fixed
- Sensitive values from `terraform plan` (marked via `before_sensitive`/
  `after_sensitive`) are now redacted in drift findings instead of being printed
  in plaintext into PR comments and SARIF output.
- Plan addresses inside modules or behind `count`/`for_each`
  (`module.db.aws_db_instance.x[0]`) are normalized before matching against the
  PR's own `.tf` diff — previously every resource inside a module was misreported
  as drift, which is the standard real-world Terraform layout.
- Data source reads (`mode: "data"` in the plan) are excluded from all phase-2
  rules; they were never meant to trigger destroy/replace/drift findings.
- `loadConfig` now applies `SCANNER_BLOCK_THRESHOLD` /
  `SCANNER_PLAN_BLAST_RADIUS_THRESHOLD` env var overrides even when no config
  file is present — previously a missing file short-circuited before the env
  checks ran, so env-only configuration silently had no effect.

### Infrastructure
- Full test coverage across all 10 packages, including a black-box integration
  suite in `cmd/scanner` that builds the real binary and runs it against
  temporary git repositories.
- MIT license, `.dockerignore`, CI (`go build` / `go vet` / `go test` / Docker
  build) on every push and PR.

---

Earlier history (pre-`v0` tag) was the initial MVP scaffold: project structure,
the four phase-1 rules, and the first Docker action packaging.
