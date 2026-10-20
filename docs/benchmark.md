# Benchmark and rule maturity

Every built-in rule is scored against a labelled corpus of Terraform cases. The scores decide
which rules may block a merge, and show what each rule catches, what it misses, and why.

The current scores are in [benchmarks/RESULTS.md](../benchmarks/RESULTS.md).

## What the corpus is, and what it is not

The cases in [`benchmarks/cases`](../benchmarks/cases) are synthetic and labelled by the
maintainers. Each case holds positives (configurations a rule must report) and near misses
(configurations that look risky at a glance and are not: `password = var.db_password`, an
egress rule to `0.0.0.0/0`, a public key in PEM format).

That makes the corpus a specification and a regression guard. It is **not** an estimate of how
the rules behave on real repositories. A precision of 100% here means the rule reports nothing
the maintainers labelled safe, on a few hundred labelled cases; it does not mean the rule never
misfires. Every score comes with its sample size for that reason. Precision on real
repositories can only come from teams running the scanner on their own code; each false
positive they report becomes a near miss in the corpus before the rule changes.

## How a case is scored

`python benchmarks/score.py` commits each case into a temporary Git repository (`base/`, then
`head/`) and scans the change with the same code path as the command line, including the plan
in `plan.json` when the case has one. The labels in `case.yml` name a rule and a target, a
resource address or `file:<path>`:

- a reported finding that matches an `expect` label is a true positive;
- an `expect` label with no matching finding is a false negative;
- any other finding of a rule the case is labelled for is a false positive, whether or not
  the target is listed under `must_not_report`.

A case is scored only for the rules it names, so a resource can also trigger rules that are
not the subject of the case without counting against them.

## Maturity levels

| Maturity | Blocks a merge | Requirement |
|---|---|---|
| `experimental` | Never | None: the rule reports and gathers evidence |
| `validated` | Only when listed in `enforce_rules` | Meets the acceptance criteria below |
| `stable` | Yes, at or above the threshold | Meets the acceptance criteria; a new rule reaches it only after its findings have been reviewed on real repositories |

Acceptance criteria, checked by `tests/test_benchmark.py` for every validated and stable rule:

- at least 5 positives and 3 near misses in the corpus;
- precision of at least 95% and recall of at least 90% on the corpus.

These are engineering targets for a small corpus, not universal security standards. With five
positives, a recall of 90% means the rule misses none of them.

The rules that shipped before maturity levels existed are `stable` because they have blocked
merges since the first releases. Each meets the acceptance criteria — building the corpus found
the defects fixed in the same release, listed in the changelog — but most have not been
measured on real repositories. That is the gap a pilot with real teams closes. New rules start
`experimental`.

## Changing a rule

1. Add the case that shows the problem: a near miss for a false positive, a positive for a
   miss. Run `python benchmarks/score.py` and check that it fails the way you expect.
2. Change the rule, then run the benchmark and the test suite.
3. Run `python benchmarks/score.py --write` and commit `benchmarks/RESULTS.md` with the change,
   so the score difference is part of the review.

Promote a rule by changing its `maturity` in `src/tfpdf/ruledef/rules.py`. Moving a rule to or
from `stable` changes what blocks a merge for every user, and is a user-facing change in the
changelog.

## Known blind spots

The corpus measures the rules on the inputs it contains. Some limits hold for every rule:

- Terraform JSON syntax (`.tf.json`) is not analysed; each such file is reported as
  `unsupported_file_format`.
- Values assigned by a `.tfvars` file, a module caller or the command line are not read into
  resources. A guard set from such a value is reported as `unresolved_value`, which is
  experimental and never blocks.
- Only the built-in provider packs (AWS and Azure) give schema-based checks
  (`unknown_attribute`, `force_new_change`, `missing_lifecycle`). Other providers get value
  checks only, and the scan says so.
- IAM policies are checked as text. A `Condition` anywhere in a policy silences the principal
  check for the whole policy, and the effect of a statement (`Allow` or `Deny`) is not read.
