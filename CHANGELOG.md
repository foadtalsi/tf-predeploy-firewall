# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
- **Phase 2: `terraform plan` analysis (optional, `--plan-json`)** — still no cloud
  credentials or terraform execution in this tool; reads a plan the user already
  generated in their own job.
  - Confirmed destroy/replace, straight from the plan's own diff engine.
  - Unexpected drift: a sensitive attribute changes in the plan but wasn't touched
    by the PR's own `.tf` diff.
  - Large blast radius: too many destroy/replace actions in one plan (configurable
    threshold).
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
