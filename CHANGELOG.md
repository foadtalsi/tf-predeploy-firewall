# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- **GitLab support.** The scanner detects GitLab CI's predefined variables
  and speaks merge requests natively: the report upserts as one MR note,
  applicable fixes post as inline discussions with the **Apply suggestion**
  button (GitLab's fence is range-relative — `suggestion:-0+2` — where
  GitHub's replaces the anchored range; the scanner renders whichever
  grammar the ambient forge uses, from the same Fix), and a new
  `--codequality-output` writes the Code Quality report GitLab's MR widget
  renders with no token at all. Suggestions refuse to post when the MR head
  moved since the scan — pinning one-click fixes to lines that no longer say
  what the scan saw is the one failure this feature must never have.
  Licensing identity falls back from `GITHUB_REPOSITORY` to
  `CI_PROJECT_PATH`, and the base ref defaults from
  `CI_MERGE_REQUEST_TARGET_BRANCH_NAME`. See
  [docs/gitlab-ci.example.yml](docs/gitlab-ci.example.yml).

  The host-neutral parts (inline comment shape, diff-hunk arithmetic,
  outcome accounting) moved to `internal/forge`, which is what a Bitbucket
  client would implement if demand ever justifies one.

- **Azure support.** Rule packs for azurerm 4.81.0, generated the same way
  the AWS ones are: the full argument surface from `terraform providers
  schema -json` (1,141 resource types), ForceNew flags extracted from the
  provider's own Go source (1,054 types carry them; azurerm registers
  resources structurally rather than via AWS's doc annotations, so it got
  its own collector for both its untyped registration maps and its typed
  `ResourceType()`/`Arguments()` resources), plus hand-curated judgment: 44
  data-holding types that warrant `prevent_destroy`, and coarse monthly
  prices for 29 types. A 41-type base pack ships free in the binary; the
  full pack is served to licensed orgs like the AWS one.

  Writing the Azure packs surfaced two fixes that were latent for AWS. The
  credential name matcher was an exact-word list (`password`, `secret`, …)
  and simply missed Azure's vocabulary — `administrator_login_password`
  carrying `"Hunter2!"` sailed through; it now matches by suffix, with the
  key-ish names (`public_key`, `kms_key_id`, `partition_key`) explicitly
  kept out, and a test pinning both directions. And genpack's schema
  resolver, when it met `Schema: someFunc()`, walked past the call and could
  mistake a nested block's schema for the resource's top level — silently
  wrong ForceNew data, not just missing. The AWS packs were regenerated
  after the fix and came out identical, so that bug never shipped wrong AWS
  data; it just would have for Azure.

- **The scanner runs at your desk, not only in CI.** Releases now attach
  static binaries for Linux, macOS and Windows (amd64/arm64), and two new
  modes make them useful without a PR: `--uncommitted` scans everything
  changed since HEAD — staged, unstaged and untracked files alike, since the
  brand-new `main.tf` nobody has `git add`ed is exactly what the question is
  about — and `--staged` scans the git index, judging partial staging on
  what the commit will actually contain. Both work on a repo's very first
  commit, exit 1 at the block threshold like CI does, and never post
  comments or report usage.

  A `.pre-commit-hooks.yaml` makes it a three-line
  [pre-commit](https://pre-commit.com) hook. This is the moment the finding
  is cheapest: before a secret enters git history, removing it is an edit;
  after, it's a rotation.

  The binary is now `cmd/tf-predeploy-firewall` (was `cmd/scanner`), so
  `go install` produces a binary with the tool's actual name, and `--version`
  reports the release it was built from (also stamped into SARIF).

- **Multi-provider plumbing.** The knowledge base loads any number of rule
  packs for any number of providers side by side — resource type prefixes
  (`aws_`, `azurerm_`, `google_`) are the namespace, so lookups need no
  routing and one provider's answers cannot change because another's pack is
  loaded. Licensed scans fetch one extended pack per provider actually used
  in the changed files (detected from block headers; `providers:` overrides),
  instead of always and only fetching AWS. `genpack --provider azurerm`
  derives every path from the provider name. Coverage now records one
  provider version per provider — the single version field it replaces was
  silently overwritten by whichever pack loaded last.

  No Azure or GCP pack ships yet; this is the plumbing that makes shipping
  one a data drop instead of a code change.

- **Every finding links to the provider documentation** for its resource type,
  pinned to the provider version the rule pack was generated from. A scanner
  that says an argument doesn't exist and offers no way to check gets argued
  with; one that links the argument list gets believed or corrected, and both
  beat a standoff. The link rides on the resource address in the PR table, in
  the inline suggestion, and in each SARIF result's properties.

  Packs describe resource types only, so a data source with no resource of the
  same name (`aws_caller_identity`, `aws_availability_zones`) gets no link.
  Guessing the URL would work most of the time and send someone to a 404 the
  rest of the time, which is the worse failure for a link whose whole job is
  to let a finding be verified.

- **Rules explain themselves in Code Scanning.** Each SARIF rule now carries a
  full description, rendered help markdown, and a `helpUri` into the new
  [`docs/rules.md`](docs/rules.md) — what the rule detects, why it is worth
  interrupting a merge for, and how to suppress or tune it. An alert opened by
  someone who never ran the scan previously showed a single sentence.

  The documentation file is generated from the same source as the SARIF help,
  and a test fails if the two drift: a category with no section would be a
  dead link in somebody's security dashboard.

- **One-click fixes.** Findings whose fix is unambiguous are now posted as
  inline review comments carrying a GitHub `suggestion` block, applied with
  the **Commit suggestion** button rather than retyped. Covers the three
  `prevent_destroy` cases and credentials written inline as string literals.

  This is a deliberately narrow feature. A suggestion is committed to the
  branch by a button press, so anything less than byte-exact would commit
  broken HCL on someone's behalf: a fix is only offered when the value is
  written inline (not reached through a variable this tool can't rewrite), it
  occupies whole lines, and the generic fix is the only correct one. Every
  other finding keeps its pasteable snippet in the summary comment, which
  still lists everything.

  The credential suggestion notes that it leaves the variable undeclared —
  Terraform then fails loudly at plan time, which is a much better outcome
  than a committed password — and that the old value remains in the branch's
  git history and needs rotating.

  Two bounds, both reported on stderr rather than applied silently: GitHub
  only accepts comments on lines present in the PR diff, and no more than 20
  inline comments are posted per review. Re-running is safe — suggestions
  already on the PR are recognized by content, not by line number, so a
  rebase or an unrelated edit above them doesn't repost the set. Disable with
  `suggestions: false`.

- **Baseline mode (`--baseline`, `--write-baseline`)** — record the findings a
  repository already has, so they stop blocking merges while anything new
  still does. This is what makes the scanner adoptable on an existing estate:
  before it, the only response to a wall of pre-existing findings was to lower
  `block_threshold` until the tool went quiet, which is uninstalling it with
  extra steps.

  Baselined findings stay visible in the PR comment, in their own collapsed
  section — the debt is never hidden, just de-fanged. Matching is on
  category + resource + file, never on line number, so an unrelated edit above
  a finding doesn't resurrect it; entries that no longer match anything are
  reported as prunable rather than silently dropped.

- **`module` and `data` blocks are scanned.** The parser only ever looked at
  `resource` blocks, which meant a mature repo — mostly module calls — was
  largely invisible, and a `module "rds" { master_password = "hunter2" }` went
  straight through. Value-based rules now apply to all three kinds;
  schema-driven rules (unknown attributes, ForceNew, prevent_destroy) stay
  resource-only, since module inputs have no provider schema to check against.

- **`var.x` and `local.y` are resolved** from `variable` defaults and `locals`
  blocks, directory-scoped the way Terraform scopes them. A password sitting
  in a variable default is a hardcoded credential one indirection away, and it
  is the more common mistake of the two; previously a single reference was
  enough to hide from every value-based rule.

  Findings name the indirection — *"resolves to a hardcoded string literal
  (via var.db_password)"* — so a report on a line that merely reads
  `var.something` doesn't read as a false positive. Anything not statically
  resolvable stays unresolved and is skipped exactly as before, so this can
  only ever surface more findings, never different ones.

## [v1.0.0] — 2026-08-13

First tagged release since `v0`, and the one that matters: everything below
had been sitting on `main` unreleased, so every workflow pinned to `@v0` was
running the July build.

**If you are on `@v0`, you were getting false positives that blocked PRs on
valid Terraform.** The `v0` tag now points here too, so no one is left on the
old build; `@v1` is the tag to pin going forward.

Nothing was removed: every `v0` action input still exists and behaves the
same, and every resource type the old schema covered is still covered (39
types now, against 33, and 71 arguments on `aws_instance` against 29).

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

## [v0] — 2026-07-14

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
