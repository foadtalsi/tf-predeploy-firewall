# Rule packs

The scanner's detection content is data, not Go. What each rule looks for,
how its finding is worded, which severity it carries, and the documentation a
reader lands on afterwards all live in one YAML file:
[`internal/ruledef/rules.yaml`](../internal/ruledef/rules.yaml).

That file is embedded into the binary, so a stock scanner needs nothing on
disk. But you can print it, edit it, and run against your version without a
Go toolchain and without waiting for a release:

```sh
tf-predeploy-firewall --print-rules > my-rules.yaml
# edit
tf-predeploy-firewall --rules my-rules.yaml
```

## Extending instead of replacing

Most of the time you want to keep the built-in rules and change one thing.
Add `extends: builtin` and the pack is layered on top of the compiled-in one
instead of replacing it — matched **by rule id**:

```yaml
version: 1
extends: builtin

rules:
  # Switch one detector off. Not the whole category: `ignore_rules:` in the
  # config can only do categories, and disabling all of tutorial_pattern to
  # silence one over-eager format would take credential detection with it.
  - id: placeholder_resource_name
    disabled: true

  # Correct a built-in by redeclaring it. Same id, your severity and wording.
  - id: hardcoded_credential
    category: tutorial_pattern
    severity: high
    match:
      scope: attribute
      literal: true
      attr_name_matches: '(?i)^(?:.*_)?(password|secret|api_key|token)$'
      value_not_one_of: ["", "true", "false"]
    message: '{attr_q} is committed in plain text — see runbook/secrets'

  # Add one of your own. New id, so it is appended.
  - id: no_public_acl
    category: org_policy
    severity: critical
    match:
      scope: attribute
      attr_names: [acl]
      literal: true
      value_matches: 'public'
    message: 'bucket ACL {value_q} is public — use a bucket policy instead'
```

```
tf-predeploy-firewall: rule pack overlay.yaml extends the built-in rules: 19 inherited, 1 overridden (hardcoded_credential), 1 added (no_public_acl), 1 disabled (placeholder_resource_name)
```

An override lands **in the position the rule it replaces held**, because order
carries meaning: a group's members are ordered alternatives. Disabling an id
that does not exist is an error rather than a no-op — it is the signature of a
typo, and the consequence of guessing would be that the rule you meant to
switch off is still running. A pack that disables every rule is refused for
the same reason.

Both packs are revalidated after merging, since two individually valid packs
can combine into an invalid one — overriding a group member with a rule of a
different scope, for instance.

## Replacing outright

Without `extends:`, `--rules` **replaces** the built-in pack. Correcting a
built-in rule is the main reason to reach for a pack at all, and an add-only
mechanism could not do it — but `extends: builtin` now covers that case more
precisely, so full replacement is for when you genuinely want only your own
rules. The failure mode is a scan running on far fewer rules than you think,
so it is announced:

```
tf-predeploy-firewall: using rule pack my-rules.yaml (21 definitions, 10 active) — the built-in rules are NOT in effect
```

## What a rule looks like

```yaml
version: 1

rules:
  - id: hardcoded_credential
    category: tutorial_pattern
    severity: critical
    match:
      scope: attribute
      literal: true
      attr_name_matches: '(?i)^(?:.*_)?(password|secret|api_key|token)$'
      value_not_one_of: ["", "true", "false"]
    message: '{attr_q} resolves to a hardcoded string literal{via}, not a secret reference'
    fix:
      action: replace_attr_line
      lines:
        - '{attr} = var.{var}'
      skip_when_resolved: true
      note: 'The old value is still in this branch history — rotate it.'
```

### `match:` — where to look

| Key | Meaning |
|---|---|
| `scope` | `attribute` (top-level), `block_attribute` (inside nested blocks), `any_attribute` (both), `resource_name` |
| `kinds` | restrict to `resource` / `data` / `module`; omit for any |
| `resource_types` | exact provider type names; omit for any |
| `block_types` | which nested blocks to walk (e.g. `[ingress, egress]`); omit for all |
| `attr_names` | exact attribute names |
| `attr_name_matches` / `attr_name_not_matches` | regex on the attribute name |
| `attr_name_contains` | case-insensitive substring of the attribute name |
| `literal` | require a statically-known value |
| `min_length` | shortest value worth judging |
| `value_matches` / `value_contains` / `value_not_one_of` | conditions on the value |
| `name_matches` | for `scope: resource_name` |
| `confirm` | a predicate applied to the substring `value_matches` found |
| `predicate` | a predicate applied to the whole value |

Every condition you set must hold. A `match:` with no conditions is rejected
at load time rather than flagging every attribute in the repository.

### `{placeholders}` — how the finding reads

`{attr}` `{attr_q}` `{value}` `{value_q}` `{resource}` `{type}` `{name}`
`{name_q}` `{block}` `{location}` `{via}` `{label}` `{bits}` `{length}`
`{var}`

The `_q` variants are quoted and escaped. `{via}` expands to
` (via var.db_password)` when the literal was reached through a reference and
to nothing otherwise, so a finding reported on a line that merely reads
`password = var.db_password` still says where the value actually lives.
Anything that is not a known placeholder is left alone — fix templates write
Terraform, and Terraform is full of braces.

### `confirm:` and `predicate:` — the compiled vocabulary

A rule declares *what* it looks for. When deciding needs more than a pattern,
it names one of these:

| Name | Kind | What it does |
|---|---|---|
| `base64_secret` | `confirm` | mixed case + digits + entropy ≥ 4.2 — tells base64 of random bytes from a long file path |
| `hex_entropy` | `confirm` | entropy ≥ 3.0 — rejects degenerate hex runs that carry no randomness |
| `looks_like_secret` | `predicate` | ≥ 24 chars, no spaces, no known-public prefix, entropy ≥ 4.4; supplies `{bits}` |

This list is the complete set of things naming can reach. **There is no
expression language and no plugin path**, deliberately: this scanner runs
inside other people's CI pipelines, and a rule format that can execute is a
rule format that can be weaponised. A rule naming a predicate the binary does
not have fails the scan loudly — skipping it would leave the rule loaded,
matching nothing, while the run still reported success.

### `group:` — ordered alternatives

Rules sharing a `group` are tried in order and the first to match a location
wins. That is what makes a JWT get reported as a JWT rather than as "a
high-entropy string": the specific formats are listed before the statistical
fallback, and the fallback never speaks about a value that already has a
name. Put the catch-all last; a test enforces it.

### `engine:` — the compiled traversals

Some checks need something no matcher expresses, and those declare an
`engine:` instead of a `match:`. They still own their identity, parameters
and documentation here — only the walk is code.

| Engine | Why it is compiled |
|---|---|
| `unknown_attribute` | needs the provider's declared attribute surface, plus edit distance to suggest the near-miss |
| `force_new_change` | needs the base revision: a ForceNew attribute is only a finding when its value actually changed |
| `missing_lifecycle` | needs the stateful-type list, and writes a whole `lifecycle` block into the source |
| `unpinned_version` | needs brace-matched scanning of raw source — `terraform { required_providers {} }` is not a resource block |
| `static_cost` | needs per-type pricing and arithmetic against the base revision |
| `confirmed_replace`, `unexpected_drift`, `large_blast_radius`, `plan_cost_impact` | read terraform's JSON plan rather than source |

This split is the point of the design rather than an unfinished edge of it.
The things this scanner does that a plan-JSON policy engine cannot — anchoring
a finding to a line, offering a fix precise enough for a one-click commit,
confirming a match with a measurement — are exactly the things a declarative
matcher cannot express. Making everything declarative would cost all three.

## `docs:` — what the reader gets

One entry per category, and [`docs/rules.md`](rules.md) is generated from it.
Every SARIF upload links there, so a category with no entry becomes a dead
link in someone's security dashboard; a test regenerates the file and fails
if it drifts.

Each entry answers four questions, and the fourth is not optional:

1. What this means
2. Why it matters
3. How to fix it
4. **If you disagree** — how to suppress or tune it

A rule you cannot turn off is a rule that gets the whole tool turned off.

## Relationship to `custom_rules:`

`custom_rules:` in your config still works exactly as before and nothing about
it has changed. It is now the legacy path: an `extends: builtin` pack does
everything it does and more, in the same vocabulary as the built-in rules, and
with documentation, fixes and severities attached.

| | `custom_rules:` | `extends: builtin` pack |
|---|---|---|
| Add a rule | yes | yes |
| Correct a built-in rule | no | yes |
| Switch off one built-in rule | no (category only) | yes |
| Nested-block scopes, entropy predicates, fixes, docs | no | yes |

Prefer a pack for anything new. `custom_rules:` is not deprecated and will
not be removed without warning — plenty of orgs only ever need "we also
forbid X", and three lines of YAML in a config file is a fair way to say it.
