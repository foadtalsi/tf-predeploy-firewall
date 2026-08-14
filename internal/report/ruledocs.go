package report

import (
	"fmt"
	"strings"
)

// docsBaseURL is where the per-rule documentation lives. It points at the
// main branch rather than a tag: a link inside a SARIF upload outlives the
// scanner version that produced it, and a reader following it a year later
// wants the current explanation, not an archived one.
const docsBaseURL = "https://github.com/foadtalsi/tf-predeploy-firewall/blob/main/docs/rules.md"

// ruleHelp is the long-form explanation of one category: what it detects,
// why it is worth a build failure, and what to do about it — including how
// to disagree with it.
//
// GitHub Code Scanning renders this on the alert page, which is where a
// finding is read by someone who did not run the scan and has no context for
// it. A rule that can't explain itself there is a rule that gets ignored or
// switched off wholesale.
type ruleHelp struct {
	fullDescription string
	markdown        string
}

var ruleHelps = map[Category]ruleHelp{
	CategoryUnknownAttribute: {
		fullDescription: "An argument that the provider does not declare for this resource type. Terraform rejects it at plan time; the value of catching it here is that nobody waits for a plan to find out.",
		markdown: `## What this means

The argument isn't part of the resource type's schema in the provider version
this scanner checked against. Terraform will reject it with
` + "`An argument named \"…\" is not expected here`" + ` — this finding is that
error, delivered before CI spends a plan on it.

## Why it matters

This is the most reliable signature of generated Terraform. A model asked for
an argument that ought to exist will produce one that sounds exactly right,
and it fails only once the plan runs — often after a reviewer has already
approved the diff.

## How to fix it

Open the linked provider documentation for the resource type and compare the
argument list. Usually it is one of:

- a near-miss on a real argument name,
- an argument that belongs in a nested block rather than at the top level,
- an argument removed in a provider major version.

## If you disagree

The argument surface is generated from the provider's own schema, so a false
positive here means the scanner's rule pack is older than your provider.
Suppress a single line with ` + "`# tf-firewall-ignore: unknown_attribute`" + `,
or the whole category with ` + "`ignore_rules`" + ` in the config.`,
	},

	CategoryTutorialPattern: {
		fullDescription: "A value that looks copied from documentation rather than chosen: a credential written as a string literal, a CIDR open to the whole internet, or a placeholder name.",
		markdown: `## What this means

The value matches a pattern that is normal in a tutorial and wrong in a real
repository — a hardcoded credential, ` + "`0.0.0.0/0`" + `, or a placeholder
name like ` + "`example`" + ` or ` + "`test`" + `.

## Why it matters

A credential committed to a repository is disclosed to everyone with read
access and stays in git history after it is removed. An ingress rule open to
` + "`0.0.0.0/0`" + ` is reachable from the entire internet, which is only ever
deliberate for a small number of ports.

## How to fix it

**Credentials:** move the value out of the repository — a variable supplied by
your secret manager, or the provider's own managed-secret support (for RDS,
` + "`manage_master_user_password = true`" + ` removes the need for a password
in configuration at all). **Then rotate the old value**: removing it from the
file does not remove it from history.

**Open CIDRs:** narrow to the ranges that actually need access. If a public
listener is the intent, that is what a suppression comment is for.

## If you disagree

Suppress one line with ` + "`# tf-firewall-ignore: tutorial_pattern`" + `. A
deliberately public load balancer is a legitimate reason; a credential is
essentially never one.`,
	},

	CategoryForceNewChange: {
		fullDescription: "A changed argument that the provider marks ForceNew, meaning apply will destroy and recreate the resource rather than update it in place.",
		markdown: `## What this means

The provider marks this argument ` + "`ForceNew`" + `: it cannot be changed on
an existing resource. Applying this diff destroys the resource and creates a
replacement.

## Why it matters

On a stateful resource this is data loss and downtime, and it does not look
like either in the diff — a one-line change to a name or an availability zone
reads as trivial. This is the finding that most often catches something a
human review missed.

## How to fix it

Decide deliberately, then make the decision visible:

- If replacement is intended, say so in the PR description, and check whether
  a snapshot or backup exists first.
- If it is not, revert the argument and reach the goal another way — many
  resources have an in-place equivalent (renaming an RDS instance's
  ` + "`identifier`" + ` is in-place; changing its ` + "`availability_zone`" + `
  is not).
- Run ` + "`terraform plan`" + ` and read the ` + "`# forces replacement`" + `
  annotations. Supplying the plan JSON to this action upgrades this heuristic
  finding into a confirmed one.

## If you disagree

Nothing is wrong with a deliberate replacement — the finding exists so that it
is deliberate. Suppress with ` + "`# tf-firewall-ignore: force_new_change`" + `
once you have decided.`,
	},

	CategoryMissingLifecycle: {
		fullDescription: "A stateful resource with no lifecycle { prevent_destroy = true } guard, leaving it exposed to accidental deletion by an apply.",
		markdown: `## What this means

This resource type holds data that cannot be recreated from configuration —
a database, a volume, a bucket — and carries no
` + "`lifecycle { prevent_destroy = true }`" + ` block.

## Why it matters

` + "`prevent_destroy`" + ` makes Terraform refuse to plan a destroy of the
resource at all. Without it, the only thing standing between a mistaken
` + "`terraform destroy`" + `, a removed block, or a ForceNew change and the
loss of production data is somebody reading the plan output carefully.

## How to fix it

` + "```hcl" + `
resource "aws_db_instance" "prod" {
  # …

  lifecycle {
    prevent_destroy = true
  }
}
` + "```" + `

This scanner posts that as an applicable suggestion on the PR where it can.

Note that ` + "`prevent_destroy`" + ` blocks the plan rather than warning about
it: intentionally destroying the resource later means removing the guard in
its own commit, which is the point — it makes the deletion an explicit,
reviewable act.

## If you disagree

Ephemeral environments are the real exception. Scope the exemption to them
with an ` + "`ignore_paths`" + ` entry rather than turning the rule off
everywhere.`,
	},

	CategoryConfirmedReplace: {
		fullDescription: "terraform plan confirms this apply destroys or replaces a stateful resource. Not a heuristic — Terraform's own diff says so.",
		markdown: `## What this means

This comes from the plan JSON you supplied, not from reading the ` + "`.tf`" + `
files: Terraform's own diff engine reports this resource as ` + "`delete`" + `
or ` + "`replace`" + `.

## Why it matters

There is no ambiguity left to argue about. If the resource holds data, this
apply loses it.

## How to fix it

Confirm a backup or snapshot exists, then decide whether the replacement is
what you meant. If it isn't, ` + "`terraform plan`" + ` output names the
attribute forcing it — the fix is to change that attribute back.

A ` + "`lifecycle { prevent_destroy = true }`" + ` guard would have turned this
into a plan-time refusal instead of an approved PR.

## If you disagree

A deliberate replacement of a resource that holds nothing you need is
legitimate. Suppress with ` + "`# tf-firewall-ignore: confirmed_replace`" + `
after checking, not before.`,
	},

	CategoryUnexpectedDrift: {
		fullDescription: "terraform plan changes a sensitive attribute that this PR's own .tf diff never touched — the change comes from somewhere else.",
		markdown: `## What this means

The plan modifies an attribute that nothing in this PR's Terraform diff
touches. The change originates elsewhere: a module version bump, a provider
upgrade, a variable's value, or infrastructure that was modified outside
Terraform.

## Why it matters

It is the change nobody is reviewing. The diff on screen doesn't contain it,
so the reviewer's attention is on a different set of lines entirely.

## How to fix it

Work out where it comes from before applying:

- ` + "`terraform plan`" + ` shows the before and after values.
- If the resource was changed by hand in the console, the plan is about to
  revert that change.
- If a module or provider upgrade caused it, read that release's changelog.

## If you disagree

Expected drift after a provider upgrade is common — suppress it for that PR
with ` + "`# tf-firewall-ignore: unexpected_drift`" + ` rather than adding
` + "`unexpected_drift`" + ` to ` + "`ignore_rules`" + ` permanently, which
turns off the only rule that watches changes nobody is reviewing.`,
	},

	CategoryLargeBlastRadius: {
		fullDescription: "The plan destroys or replaces an unusually large number of resources at once.",
		markdown: `## What this means

The count of destroy and replace actions in this plan is above the configured
threshold (` + "`plan_blast_radius_threshold`" + `, default 10).

## Why it matters

Large replacements are usually a symptom rather than an intent — a renamed
module, a changed ` + "`for_each`" + ` key, a moved resource — and they are
exactly the plans people approve without reading to the end.

## How to fix it

Check whether the resources are being **moved** rather than replaced. If they
are, ` + "`moved`" + ` blocks (or ` + "`terraform state mv`" + `) preserve them
and reduce the plan to nothing. If the replacement is real, consider splitting
the change into several applies.

## If you disagree

Tearing down a whole environment is a legitimate large plan. Raise
` + "`plan_blast_radius_threshold`" + ` for a repo where that is routine.`,
	},

	CategoryCostImpact: {
		fullDescription: "The plan increases the estimated monthly bill by more than the configured threshold. Estimates are coarse and on-demand-only.",
		markdown: `## What this means

Summing the coarse per-type prices in the rule pack, this plan raises the
estimated monthly cost by more than ` + "`cost_impact_threshold_usd`" + `.

## Why it matters

Cost mistakes in Terraform are silent and recurring. A wrong instance size or
a forgotten NAT gateway bills every hour until somebody reads an invoice, and
the diff that introduced it looked like one word.

## How to fix it

Check the resource types and sizes the finding names. The most common causes
are an oversized instance class copied from an example, a NAT gateway where a
gateway endpoint would do, and provisioned capacity left at a default.

## Accuracy

These are **estimates**, deliberately coarse: on-demand list prices, no
reserved instances, no savings plans, no data transfer, no per-request
charges. Treat a finding as a prompt to look, not as a quote. Set
` + "`cost_impact_threshold_usd: 0`" + ` to switch the category off.`,
	},
}

// ruleHelpURI links to a category's section in the published rule
// documentation.
func ruleHelpURI(c Category) string {
	return fmt.Sprintf("%s#%s", docsBaseURL, c)
}

// RenderRuleDocs generates docs/rules.md from ruleHelps.
//
// The file is generated rather than written by hand because helpUri points
// at it from every SARIF upload: a category whose section doesn't exist is a
// dead link in someone's security dashboard, and the only way to be sure the
// two agree is to have one produce the other. A test regenerates and compares.
//
// Headings are the bare category ID so the anchors helpUri builds
// (#unknown_attribute) are exactly what GitHub generates; the readable label
// goes underneath.
func RenderRuleDocs() string {
	var b strings.Builder

	b.WriteString(`<!-- Generated by internal/report/ruledocs.go. Do not edit by hand:
     run "go test ./internal/report -run TestRuleDocs -update" instead. -->

# Rules

Every finding this scanner produces belongs to one of the categories below.
Each says what it detects, why it is worth interrupting a merge for, and how
to disagree with it — a rule you can't turn off is a rule that gets the whole
tool turned off.

Suppression works at four levels, narrowest first:

| Scope | How |
|---|---|
| One line | ` + "`# tf-firewall-ignore: <category>`" + ` above or on the line |
| One path | ` + "`ignore_paths:`" + ` in ` + "`.github/tf-firewall.yml`" + `, optionally scoped to categories |
| One category, everywhere | ` + "`ignore_rules:`" + ` in the same file |
| Everything that exists today | a committed baseline (` + "`--write-baseline`" + `) — keeps findings visible but non-blocking |

`)

	for _, r := range sarifRules {
		c := Category(r.ID)
		h, ok := ruleHelps[c]
		if !ok {
			continue
		}
		// The help markdown is written to stand alone on a Code Scanning
		// alert page, where "##" is the top level. Nested under a category
		// heading here, it has to drop one level.
		body := strings.ReplaceAll("\n"+h.markdown, "\n## ", "\n### ")

		fmt.Fprintf(&b, "## %s\n\n**%s**\n\n%s\n%s\n\n---\n\n",
			c, categoryDisplay(c), h.fullDescription, body)
	}

	b.WriteString("Custom rules defined in your own config get the category `custom:<id>` " +
		"and are documented by whatever `message:` you give them.\n")

	return b.String()
}
