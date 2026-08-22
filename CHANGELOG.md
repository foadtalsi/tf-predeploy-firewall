# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed
- **L'analyseur ne peut plus boucler indéfiniment.** Une compréhension `for`
  dont la clé passe à la ligne après le `:` — la forme que `terraform fmt`
  produit lui-même sur une expression un peu longue — faisait tourner le
  scanner sans jamais rendre la main. Dans une CI, le job partait jusqu'à son
  délai sans le moindre message.

  Deux corrections, parce que le déclencheur n'a pas à être le dernier : les
  sauts de ligne sont désormais ignorés là où HCL les autorise à l'intérieur
  d'une compréhension, et la boucle qui lit le corps d'un fichier garantit
  qu'un tour ne peut pas se terminer sans avoir consommé un jeton. Le pire
  qu'une entrée incomprise puisse produire est un diagnostic.

  Le binaire Go n'a jamais eu ce défaut, `hashicorp/hcl` s'en chargeant pour
  lui ; les tests différentiels le confirment.

### Changed
- **Le scanner est réécrit en Python.** Même produit, même version, mêmes
  règles, mêmes sorties : le SARIF et le rapport GitLab Code Quality sont
  identiques octet pour octet à ceux que produisait le binaire Go, et une
  suite de tests différentiels le vérifie contre lui.

  Ce qui change pour vous : l'image de l'Action est maintenant
  `python:3.12-slim` au lieu d'un binaire statique, et le paquet s'installe
  aussi depuis PyPI (`pip install tf-predeploy-firewall`). Les drapeaux de la
  ligne de commande sont inchangés, y compris les formes à un seul tiret
  (`-base-ref`) et `--drapeau=false`, que le paquet `flag` de Go acceptait.

  Un seul comportement diffère volontairement. Quand deux découvertes tombent
  sur le même fichier et la même ligne, leur ordre relatif dans le commentaire
  de PR était décidé par le tri de Go, qui n'est pas stable ; il est désormais
  spécifié (catégorie puis message). Les mêmes découvertes, dans un ordre qui
  ne bougera plus d'une version à l'autre.

  L'analyseur HCL2 est écrit à la main plutôt que pris sur PyPI : les
  bibliothèques disponibles rendent des dictionnaires et perdent la ligne et
  la colonne, dont dépend chaque sortie de cet outil.


### Added
- **Eleven new detectors for guards that were explicitly switched off**, in
  four new categories: `public_exposure`, `encryption_disabled`,
  `permissive_iam` and `audit_disabled`.

  Found by measurement rather than by brainstorm. A corpus of 132 lines of
  realistic generated Terraform — a public database, a world-readable bucket,
  an S3 public-access block with all four switches off, IMDSv1, unencrypted
  volumes, a plaintext-capable TLS policy, a disabled CloudTrail, and three
  shapes of wildcard IAM policy — produced **five findings, all of them the
  same rule (`missing_lifecycle`), none of them blocking**. Fourteen genuinely
  dangerous lines, none reported. The same corpus now produces twenty-two
  findings and blocks the merge.

  What is new:

  - `public_data_store` — `publicly_accessible = true` on RDS, Aurora,
    Redshift, DMS.
  - `public_acl` — `public-read`, `public-read-write`, and `authenticated-read`,
    which reads as a restriction and means every AWS user on earth.
  - `s3_public_access_block_disabled` — any of the four switches set to
    `false`, on the resource whose entire purpose is that they are true.
  - `imds_v1_allowed` — `http_tokens = "optional"`, the SSRF-to-credentials
    path of the 2019 Capital One breach.
  - `encryption_at_rest_disabled` / `encryption_in_transit_disabled` — six and
    four attribute spellings respectively, set to `false`.
  - `weak_tls_policy` — a policy still naming TLS 1.0/1.1.
  - `audit_logging_disabled` — a trail switched off, scoped by resource type
    so a paused autoscaling schedule is not reported as a compliance failure.
  - `skip_final_snapshot` — filed under `missing_lifecycle`, because it is the
    same concern the reader already has documentation for.
  - `iam_wildcard` (compiled) and two declarative rules for
    `aws_iam_policy_document`.

  **Written values only, never an absent one.** That is the discipline the
  whole group is built on: a missing `encrypted` is the provider default on
  hundreds of resource types, and a scanner reporting defaults gets muted,
  taking its true positives with it. `encrypted = false` is a decision
  somebody made and a reviewer can be asked about.

  Deliberately not reported: `Resource: "*"` on its own, since a large family
  of actions takes no ARN (`s3:ListAllMyBuckets`, `ec2:Describe*`); a
  `Principal: "*"` narrowed by any `Condition`, which is the correct org-wide
  pattern; and an HTTP listener, because a port-80 listener that redirects to
  443 is right and the matcher cannot see the sibling block that would tell
  them apart.

  Verified against noise as well as detection: zero findings from these
  categories on 28 files of real production Terraform, and a
  `insecure_config_clean.tf` fixture of correct code is pinned in the same
  golden file as the positive corpus — so widening a pattern to catch one
  more real case shows up immediately as noise appearing in the clean half.

- **`iam_wildcard`, a compiled rule, because the matcher cannot see into a
  policy.** The form the AWS documentation uses and generated Terraform
  reproduces is `policy = jsonencode({…})` — a function call over an object,
  which the parser resolves to nothing, so `value_matches` has nothing to
  match against. Writing the rule only for heredoc policies, which do arrive
  as literals, would have caught the rarer spelling and missed the common one.
  It reads the attribute's raw source range instead, the same technique
  `unpinned_version` already uses, and reports the line the wildcard is
  actually on rather than the line the attribute starts on.

- **A second golden file, run against the full rule set.** The existing one
  covers a single category's detectors, which cannot show a new rule
  double-reporting a line another rule already covers. `testdata/golden/insecure_config.txt`
  runs every default rule over both the positive and the negative fixture.

### Fixed
- **A credential in a nested block was found by nothing at all.** Not a gap
  but a dead zone, produced by two rules interacting: the value-pattern
  checks deliberately skip attributes whose *name* already looks like a
  credential, so as not to report the same line twice — and the name check
  only walked top-level attributes. A nested `client_secret` was therefore
  excluded from the value checks for having a credential name, and excluded
  from the name check for being nested.

  `service_principal { client_secret = "AKIA…" }` on an AKS cluster — a
  literal AWS key, in a block shape that is entirely ordinary — produced no
  finding whatsoever. `auth { password }` and `environment { variables }`
  were equally invisible.

  The name rule now walks nested attributes too, and says which block the
  finding is in. The suggested variable name carries the block type
  (`prod_service_principal_client_secret`), since one resource can hold two
  blocks declaring the same attribute and a shared variable name would have
  the second fix quietly redefine the first.

  Purely additive: over the corpus this adds one finding and changes none.
  It was invisible to the existing tests because each rule was correct on its
  own — only their combination lost the attribute.

### Added
- **Rule packs can extend the built-in ones instead of replacing them.**
  `extends: builtin` layers a pack over the compiled-in rules, matched by
  rule id: override one to change its severity or wording, `disabled: true`
  to switch a single detector off, a new id to add your own. Everything else
  is inherited, and the scan reports exactly what happened.

  The two things people want are opposites — adding an org's rule must not
  silently drop the built-in ones, and correcting a built-in that misfires
  must be possible at all, which an add-only mechanism cannot do. Overriding
  by id is both, and it makes "change one severity" a four-line file rather
  than a fork of the whole pack.

  An override keeps the position of the rule it replaces, because order
  carries meaning: a group's members are ordered alternatives. Disabling an
  id that does not exist is an error rather than a no-op — it is what a typo
  looks like, and the consequence of guessing would be that the rule you
  meant to switch off is still running. Merged packs are revalidated from
  scratch, since two valid packs can combine into an invalid one.

  This makes `custom_rules:` the legacy path. It is unchanged and is not
  going away — three lines of config is a fair way to say "we also forbid
  X" — but a pack does everything it does, in the same vocabulary as the
  built-in rules.

### Changed
- **The detection rules are data, not Go.** What each built-in rule looks
  for, its severity, the wording of its finding, the one-click fix it offers
  and the documentation a reader lands on are now declarations in a YAML rule
  pack (`internal/ruledef/rules.yaml`), embedded in the binary. `--print-rules`
  writes it out and `--rules <file>` runs against your edited copy — no Go
  toolchain, no release. A pattern that misfires on your repository is
  something you can correct today.

  Rules were in Go for no better reason than that the scanner is; the cost
  was that improving a sentence someone found confusing, or narrowing a
  regex that overfired, required a release. Four hundred lines of the rule
  documentation were Markdown inside Go string literals.

  What did *not* move is the more interesting half. Anchoring a finding to a
  line, offering a fix precise enough for GitHub's "Commit suggestion"
  button, and confirming a match by measuring it are exactly what a
  declarative matcher cannot express — and exactly what this scanner does
  that a plan-JSON policy engine does not. Those traversals stay compiled and
  declare themselves in the pack with an `engine:` key, so a rule's identity,
  parameters and documentation still live in one file. The vocabulary a rule
  may invoke is a fixed list of named predicates with no expression language
  and no plugin path: this runs inside other people's CI, and a rule format
  that can execute is one that can be weaponised.

  Verified by pinning all 27 findings a purpose-built corpus produces —
  messages, suggestions, fixes and notes in full — before the change and
  asserting them after, and by diffing a full scan of this project's own
  infrastructure: 39 findings, byte-identical. `docs/rules.md` regenerated
  from the pack differs from the previous version only in the line naming
  what generated it.

  `custom_rules:` in your config is untouched and still adds to the built-in
  rules. See `docs/rule-packs.md`.

### Added
- **Rule packs refresh themselves weekly.** A scheduled workflow resolves the
  newest AWS and Azure provider releases, regenerates both packs, verifies
  the scanner still builds and passes against them, and opens one PR per
  provider when anything changed.

  Staleness here is not reduced coverage, it is false positives: arguments
  added by a new provider release are absent from an old pack, so the
  unknown-attribute rule reports valid Terraform as hallucinated — at
  severity high, which blocks a PR. Both providers ship roughly weekly.

  It opens a PR rather than pushing: a pack change alters what every
  customer's CI blocks on, and the generation summary (types covered,
  ForceNew resolution rate) is exactly what a human should glance at first —
  a sharp drop in that rate means the provider restructured its source and
  the extractor needs attention, not that the data changed.

- **Unpinned module and provider versions are flagged.** A registry module
  with no `version`, a git source with no `?ref=`, a `?ref=main` anyone can
  move, or a provider in `required_providers` with no constraint. Two
  problems, and the second is the serious one: the plan a reviewer approved
  and the plan that runs an hour later can differ with no commit here to
  explain it, and whoever can push to that branch decides what runs against
  your cloud account with your credentials.

  It belongs beside the hallucination checks because generated Terraform
  almost never writes a version constraint — a model asked for "a VPC
  module" emits a source and moves on. Local modules (`./modules/vpc`) are
  never flagged: this repository's history is their version. Nor is a ref
  whose shape isn't recognised, since accusing someone's release scheme of
  being a branch would be a false positive.

- **`.tfvars` files are scanned.** They were invisible, which was the widest
  gap between what this tool claimed and what it did: a `.tfvars` file is by
  design the place values live, so someone told to move a password out of
  `main.tf` very often moves it into `terraform.tfvars` and commits that.
  The tool's own suggested fix even recommended "a tfvars file that isn't
  committed" — while never checking whether one was.

  `terraform.tfvars`, `*.auto.tfvars` and their `.json` forms are all
  covered, in every scan mode, with nested objects and lists walked so a
  credential inside a map of settings is found too. Values are judged by
  exactly the same standard as resource attributes — the credential-name,
  known-format, entropy and open-CIDR checks are shared, not reimplemented.

  Only git-tracked files reach the scanner, so a properly gitignored
  `.tfvars` is never flagged. And because the same scan runs pre-commit, the
  advice is worded as the condition it is: rotation is required *if the file
  is already committed*, not asserted as fact when nothing is disclosed yet.

### Fixed
- **A build command was reported as a leaked AWS secret key.** The 40-char
  base64 pattern matched any long run of `[a-z0-9/+]`, which an ordinary file
  path reaches easily — `infra/terraform/build/dashboard/bootstrap` is 41 —
  so a `local-exec` command was flagged at *critical* severity. Found by
  running the scanner against this project's own Terraform.

  A credential pattern may now carry a confirmation check applied to the
  matched text. The base64 one requires mixed case, digits and high entropy
  (which base64 of random bytes has and a lowercase path does not); the
  "high-entropy hex string" pattern now actually measures entropy, so a
  repetitive run of valid hex characters no longer qualifies. Detection of
  real keys is unchanged — AWS's own canonical example secret still matches.

- **A GCP repo was told it had coverage it never had.** `google` was listed
  as a fetchable provider in v1.1.0 while no GCP pack was ever generated, so
  a licensed scan announced that coverage "falls back to the embedded pack"
  for a provider with no embedded pack — degraded coverage reported where
  there was none. GCP is removed until a pack ships: a provider is listed
  once its packs exist, not before.

  The silent half of that defect is fixed too, for every provider. Value-based
  rules (credentials, entropy, open CIDRs, custom rules) need no schema and
  fire on any provider, so an uncovered one previously produced a report that
  looked complete while the schema-driven rules sat inert. The scan now names
  the uncovered providers and states exactly which checks did and did not run.
  Utility providers (`random`, `tls`, `null`, …) are exempt — they will never
  have a pack, and warning about them every scan would train people to skip
  the line that matters.

## [v1.1.0] — 2026-08-14

### Added
- **High-entropy secret detection.** Known formats (AWS keys, JWTs, PEM
  headers, GitHub tokens) were already caught by shape; the random API token
  some SaaS minted has no shape at all, and enumerating every vendor's
  format is a race that can't be won. Randomness is the one property they
  all share, so string literals ≥24 chars with per-character entropy above
  what any cloud identifier format produces are now flagged — at `high`, not
  `critical`, because a statistical accusation must not claim certainty.
  Tuned against false positives first: ARNs, resource IDs, UUIDs, URLs and
  Azure resource paths are excluded by prefix or fall below the threshold
  naturally, and the test pins both directions. Known formats still win —
  an AKIA key reports as an AWS key, never vaguely as entropy.

- **Cost estimation without a plan.** `cost_impact_threshold_usd` now works
  on repos that never wire a plan JSON into the scan: a static estimator
  reads the `.tf` diff directly — a new resource of a priced type at its
  list price, a pricing-driving attribute change as its before/after delta.
  Decreases never fire, and count/for_each are deliberately ignored rather
  than guessed at. When a plan JSON is supplied, only the plan-based
  estimator runs — the same PR is never billed twice by two estimators that
  could disagree.

- **`--rules-dry-run`.** Tests the config's `custom_rules` against the whole
  repo and prints what each rule matched — including "0 match(es)", which is
  the line a rule author most needs: a rule that silently matches nothing
  looks exactly like a working one until the incident it should have caught.
  Always exits 0 (except on a config that doesn't parse), posts nothing,
  reports no usage, applies no suppressions.

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

  This is the plumbing that made shipping the Azure pack (above) a data
  drop instead of a code change; a GCP pack would land the same way.

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
