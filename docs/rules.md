<!-- Generated from tfpdf/ruledef/rules.py. Do not edit by hand:
     edit the pack, then run "pytest --update-docs". -->

# Rules

Every finding this scanner produces belongs to one of the categories below.
Each says what it detects, why it is worth interrupting a merge for, and how
to disagree with it — a rule you can't turn off is a rule that gets the whole
tool turned off.

Suppression works at four levels, narrowest first:

| Scope | How |
|---|---|
| One line | `# tf-firewall-ignore: <category>` above or on the line |
| One path | `ignore_paths:` in `.github/tf-firewall.yml`, optionally scoped to categories |
| One category, everywhere | `ignore_rules:` in the same file |
| Everything that exists today | a committed baseline (`--write-baseline`) — keeps findings visible but non-blocking |

## unknown_attribute

**Unknown/hallucinated attribute**

An argument that the provider does not declare for this resource type. Terraform rejects it at plan time; the value of catching it here is that nobody waits for a plan to find out.

### What this means

The argument isn't part of the resource type's schema in the provider version
this scanner checked against. Terraform will reject it with
`An argument named "…" is not expected here` — this finding is that
error, delivered before CI spends a plan on it.

### Why it matters

This is the most reliable signature of generated Terraform. A model asked for
an argument that ought to exist will produce one that sounds exactly right,
and it fails only once the plan runs — often after a reviewer has already
approved the diff.

### How to fix it

Open the linked provider documentation for the resource type and compare the
argument list. Usually it is one of:

- a near-miss on a real argument name,
- an argument that belongs in a nested block rather than at the top level,
- an argument removed in a provider major version.

### If you disagree

The argument surface is generated from the provider's own schema, so a false
positive here means the scanner's rule pack is older than your provider.
Suppress a single line with `# tf-firewall-ignore: unknown_attribute`,
or the whole category with `ignore_rules` in the config.

---

## unpinned_version

**Unpinned module or provider version**

A module source or provider requirement with no version pin. The plan that was reviewed and the plan that runs later can differ with no commit in this repository to explain why.

### What this means

A dependency floats instead of naming a version: a registry module with no
`version`, a git source with no `?ref=`, or a `?ref=main`
that points at a branch someone can push to. Or a provider in
`required_providers` with no `version` constraint.

### Why it matters

Two distinct problems, and the second is the serious one:

**Reproducibility.** The plan a reviewer approved and the plan that runs an
hour later can differ, because a third party published a release or moved a
branch. Nothing in this repository records that, so when the apply goes
wrong there is no commit to look at.

**Supply chain.** Whoever can push to that branch decides what Terraform
runs against your cloud account, with your credentials. A pinned tag can
still be moved; a commit SHA cannot.

This rule sits next to the AI-hallucination checks for a reason: generated
Terraform almost never writes a version constraint. A model asked for "a VPC
module" emits a source and moves on.

### How to fix it

```hcl
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"                          # registry: add version
}

module "internal" {
  source = "git::https://github.com/org/mod.git?ref=v1.4.2"   # tag…
}

module "critical" {
  source = "git::https://github.com/org/mod.git?ref=9f8a1c2"  # …or a SHA
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}
```

A `.terraform.lock.hcl` committed alongside pins provider versions
exactly, and is worth having regardless of the constraint above.

### If you disagree

A local module (`./modules/vpc`) is versioned by this repository's
own history and is never flagged. If you deliberately track a branch — an
internal module you also own, released continuously — suppress with
`# tf-firewall-ignore: unpinned_version`, or the category with
`ignore_rules`.

---

## tutorial_pattern

**Tutorial-copy pattern**

A value that looks copied from documentation rather than chosen: a credential written as a string literal, a CIDR open to the whole internet, or a placeholder name.

### What this means

The value matches a pattern that is normal in a tutorial and wrong in a real
repository — a hardcoded credential, `0.0.0.0/0`, or a placeholder
name like `example` or `test`.

### Why it matters

A credential committed to a repository is disclosed to everyone with read
access and stays in git history after it is removed. An ingress rule open to
`0.0.0.0/0` is reachable from the entire internet, which is only ever
deliberate for a small number of ports.

### How to fix it

**Credentials:** move the value out of the repository — a variable supplied by
your secret manager, or the provider's own managed-secret support (for RDS,
`manage_master_user_password = true` removes the need for a password
in configuration at all). **Then rotate the old value**: removing it from the
file does not remove it from history.

**Open CIDRs:** narrow to the ranges that actually need access. If a public
listener is the intent, that is what a suppression comment is for.

### If you disagree

Suppress one line with `# tf-firewall-ignore: tutorial_pattern`. A
deliberately public load balancer is a legitimate reason; a credential is
essentially never one.

---

## force_new_change

**ForceNew change on stateful resource**

A changed argument that the provider marks ForceNew, meaning apply will destroy and recreate the resource rather than update it in place.

### What this means

The provider marks this argument `ForceNew`: it cannot be changed on
an existing resource. Applying this diff destroys the resource and creates a
replacement.

### Why it matters

On a stateful resource this is data loss and downtime, and it does not look
like either in the diff — a one-line change to a name or an availability zone
reads as trivial. This is the finding that most often catches something a
human review missed.

### How to fix it

Decide deliberately, then make the decision visible:

- If replacement is intended, say so in the PR description, and check whether
  a snapshot or backup exists first.
- If it is not, revert the argument and reach the goal another way — many
  resources have an in-place equivalent (renaming an RDS instance's
  `identifier` is in-place; changing its `availability_zone`
  is not).
- Run `terraform plan` and read the `# forces replacement`
  annotations. Supplying the plan JSON to this action upgrades this heuristic
  finding into a confirmed one.

### If you disagree

Nothing is wrong with a deliberate replacement — the finding exists so that it
is deliberate. Suppress with `# tf-firewall-ignore: force_new_change`
once you have decided.

---

## missing_lifecycle

**Missing prevent_destroy**

A stateful resource with no lifecycle { prevent_destroy = true } guard, leaving it exposed to accidental deletion by an apply.

### What this means

This resource type holds data that cannot be recreated from configuration —
a database, a volume, a bucket — and carries no
`lifecycle { prevent_destroy = true }` block.

### Why it matters

`prevent_destroy` makes Terraform refuse to plan a destroy of the
resource at all. Without it, the only thing standing between a mistaken
`terraform destroy`, a removed block, or a ForceNew change and the
loss of production data is somebody reading the plan output carefully.

### How to fix it

```hcl
resource "aws_db_instance" "prod" {
  # …

  lifecycle {
    prevent_destroy = true
  }
}
```

This scanner posts that as an applicable suggestion on the PR where it can.

Note that `prevent_destroy` blocks the plan rather than warning about
it: intentionally destroying the resource later means removing the guard in
its own commit, which is the point — it makes the deletion an explicit,
reviewable act.

### If you disagree

Ephemeral environments are the real exception. Scope the exemption to them
with an `ignore_paths` entry rather than turning the rule off
everywhere.

---

## public_exposure

**Reachable from the internet**

A setting that places a resource, or the data in it, on the public internet — an explicit value, not an omitted default.

### What this means

Something in this resource was set to a value that makes it reachable from
outside your network: a database given a public address, a bucket ACL that
grants to everyone, a public-access block switched off, or an instance left
answering the older metadata service.

Each of these is an attribute somebody typed. This category never reports a
missing setting — an absent `publicly_accessible` is the safe default on
every type here, and flagging defaults is how a scanner gets muted.

### Why it matters

Public exposure is the shortest path there is between a configuration
mistake and a breach, and it needs no other bug to be exploitable. A
publicly-addressable database is protected by nothing but its security
group; a `public-read` bucket is protected by nothing at all. The IMDSv1
case is one step longer and just as well-trodden: any server-side request
forgery in software on the instance can read the instance role's temporary
credentials from 169.254.169.254, which is the shape of the 2019 Capital One
breach.

### How to fix it

- `publicly_accessible = true` → set it to `false` and reach the database
  from inside the VPC: a bastion, a VPN, or an SSM Session Manager
  port-forward.
- `acl = "public-read"` → serve the objects through CloudFront with an
  origin access identity, and leave the bucket private. Note that
  `authenticated-read` means every AWS user anywhere, not every user of
  your account.
- `block_public_*  = false` → set them back to `true`. This resource exists
  to make the bucket un-publishable regardless of any future ACL or policy;
  with a switch off, that guarantee is gone.
- `http_tokens = "optional"` → `"required"`. IMDSv2 needs a PUT to obtain a
  token first, which an SSRF cannot perform.

### If you disagree

A deliberately public bucket or a throwaway database is a real thing to
have. Suppress the single line with `# tf-firewall-ignore: public_exposure`,
which keeps the decision next to the code that made it, or the whole
category with `ignore_rules` in the config.

---

## encryption_disabled

**Encryption switched off**

Encryption at rest or in transit explicitly disabled, or a TLS policy that still permits TLS 1.0/1.1.

### What this means

An attribute that turns encryption on was set to `false`, or a TLS policy
names a protocol version that is no longer considered secure.

As with everything in this group, only written values are reported. A
resource with no `encrypted` attribute at all is not a finding here.

### Why it matters

Encryption at rest is the control that makes a stolen disk, a leaked
snapshot or a mis-shared backup a non-event rather than a disclosure. On
most resource types it is also **ForceNew**: it cannot be turned on later
without replacing the resource and moving the data, so it is decided in the
commit that creates it or not at all. That is the reason this is worth
stopping a merge for and a missing tag is not.

Encryption in transit is what stops anything on the network path reading the
traffic — inside a VPC that includes any other compromised workload in it.

TLS 1.0 and 1.1 are deprecated by RFC 8996, outside the PCI DSS accepted
set, and refused by current browsers. A policy naming them is nearly always
a value copied from an old example rather than a compatibility requirement
somebody measured.

### How to fix it

Set the flag to `true`. If the resource already exists, check the plan
before applying: for at-rest encryption on most types, Terraform will show a
replacement, and the data has to be migrated deliberately rather than by
letting the apply do it.

For a TLS policy, move to the current recommended set — on an AWS load
balancer that is `ELBSecurityPolicy-TLS13-1-2-2021-06` or later.

### If you disagree

A genuinely old client population is a real constraint, and the teams that
have one know they have one. `# tf-firewall-ignore: encryption_disabled` on
the line, or `ignore_rules` for the category.

---

## permissive_iam

**Wildcard IAM policy**

An IAM policy document granting every action, or granting to every principal with no condition narrowing it.

### What this means

A policy attached to this resource contains `Action: "*"` — every action in
every AWS service — or names `Principal: "*"` with no `Condition` limiting
who that is.

The check reads the policy from source rather than from the resource model,
because the form nearly everyone writes is `jsonencode({ … })`: a function
call over an object, which no value matcher can see inside. Heredoc and
plain-JSON policies are read the same way.

### Why it matters

`Action: "*"` with `Resource: "*"` is administrator access. It includes the
IAM actions, which means a holder can grant itself anything it was not
already given — so the blast radius of any compromise of that role is the
whole account, and no later tightening of other policies constrains it.

`Principal: "*"` on a resource policy means every AWS account on earth, not
every principal in yours. It is the difference between an internal bucket
and a public one, written in a place people rarely re-read.

Both are what a language model produces when it does not know the exact
action names, because a wildcard is the answer that always works.

### How to fix it

Name the actions the workload actually performs and the resources it
performs them on:

```hcl
Action   = ["s3:GetObject", "s3:PutObject"]
Resource = ["${aws_s3_bucket.data.arn}/*"]
```

If a public principal is genuinely wanted, narrow it with a condition —
`aws:PrincipalOrgID` for org-wide access, `aws:SourceArn` for a specific
service:

```hcl
Condition = {
  StringEquals = { "aws:PrincipalOrgID" = "o-example" }
}
```

### What this deliberately does not report

`Resource: "*"` on its own. A large family of actions takes no resource ARN
at all — `s3:ListAllMyBuckets`, `ec2:Describe*`, most of `iam:List*` — so a
rule that flagged it would fire on a large share of correct policies. It is
reported only alongside a wildcard action, where the pair means
administrator.

A `Principal: "*"` in a document that also carries a `Condition`. That is
the org-wide pattern and it is correct.

### If you disagree

A break-glass role or a deliberately public read policy is legitimate.
`# tf-firewall-ignore: permissive_iam`, or `ignore_rules` for the category.

---

## audit_disabled

**Audit logging switched off**

A trail or diagnostic setting whose logging is explicitly disabled — the record of what happened, turned off in configuration.

### What this means

A resource whose only job is to keep a record has `enable_logging = false`
or `enabled = false`.

Scoped tightly by resource type on purpose. `enabled = false` appears on
hundreds of unrelated blocks, and matching the bare attribute name would
report a paused autoscaling schedule as a compliance failure.

### Why it matters

An audit trail is the only thing that can answer what happened, after the
fact, when it matters. Its value is entirely retrospective: it has to have
been running *before* the incident, so a trail switched off today is a
question that becomes unanswerable for every day it stays off. Unlike most
findings, this one cannot be fixed retroactively.

It is also, in most regulated frameworks, a control that is asserted rather
than checked — SOC 2, PCI DSS and ISO 27001 all assume the log exists.

### How to fix it

Set it back to `true`. If the trail is disabled because it is noisy or
expensive, the usual answers are an event selector that narrows what is
recorded, or a lifecycle policy on the destination bucket — both keep the
record while reducing what it costs.

### If you disagree

A trail deliberately parked in a sandbox account is reasonable.
`# tf-firewall-ignore: audit_disabled` on the line, or `ignore_rules` for
the category.

---

## confirmed_replace

**Confirmed destroy/replace (from terraform plan)**

terraform plan confirms this apply destroys or replaces a stateful resource. Not a heuristic — Terraform's own diff says so.

### What this means

This comes from the plan JSON you supplied, not from reading the `.tf`
files: Terraform's own diff engine reports this resource as `delete`
or `replace`.

### Why it matters

There is no ambiguity left to argue about. If the resource holds data, this
apply loses it.

### How to fix it

Confirm a backup or snapshot exists, then decide whether the replacement is
what you meant. If it isn't, `terraform plan` output names the
attribute forcing it — the fix is to change that attribute back.

A `lifecycle { prevent_destroy = true }` guard would have turned this
into a plan-time refusal instead of an approved PR.

### If you disagree

A deliberate replacement of a resource that holds nothing you need is
legitimate. Suppress with `# tf-firewall-ignore: confirmed_replace`
after checking, not before.

---

## unexpected_drift

**Unexpected drift (from terraform plan)**

terraform plan changes a sensitive attribute that this PR's own .tf diff never touched — the change comes from somewhere else.

### What this means

The plan modifies an attribute that nothing in this PR's Terraform diff
touches. The change originates elsewhere: a module version bump, a provider
upgrade, a variable's value, or infrastructure that was modified outside
Terraform.

### Why it matters

It is the change nobody is reviewing. The diff on screen doesn't contain it,
so the reviewer's attention is on a different set of lines entirely.

### How to fix it

Work out where it comes from before applying:

- `terraform plan` shows the before and after values.
- If the resource was changed by hand in the console, the plan is about to
  revert that change.
- If a module or provider upgrade caused it, read that release's changelog.

### If you disagree

Expected drift after a provider upgrade is common — suppress it for that PR
with `# tf-firewall-ignore: unexpected_drift` rather than adding
`unexpected_drift` to `ignore_rules` permanently, which
turns off the only rule that watches changes nobody is reviewing.

---

## large_blast_radius

**Large blast radius (from terraform plan)**

The plan destroys or replaces an unusually large number of resources at once.

### What this means

The count of destroy and replace actions in this plan is above the configured
threshold (`plan_blast_radius_threshold`, default 10).

### Why it matters

Large replacements are usually a symptom rather than an intent — a renamed
module, a changed `for_each` key, a moved resource — and they are
exactly the plans people approve without reading to the end.

### How to fix it

Check whether the resources are being **moved** rather than replaced. If they
are, `moved` blocks (or `terraform state mv`) preserve them
and reduce the plan to nothing. If the replacement is real, consider splitting
the change into several applies.

### If you disagree

Tearing down a whole environment is a legitimate large plan. Raise
`plan_blast_radius_threshold` for a repo where that is routine.

---

## cost_impact

**Estimated cost impact**

The change increases the estimated monthly bill by more than the configured threshold. Estimates are coarse and on-demand-only.

### What this means

Summing the coarse per-type prices in the rule pack, this change raises the
estimated monthly cost by more than `cost_impact_threshold_usd`.

With a plan JSON supplied, the estimate reads Terraform's own diff (counts
and for_each included). Without one, a static estimate reads the `.tf`
source directly — new resources of priced types, and changes to the
attribute that drives a type's price — with no multipliers, since inventing
a fleet size would be worse than understating one. When a plan is supplied,
only the plan-based estimate runs; the same PR is never billed twice by two
estimators that could disagree.

### Why it matters

Cost mistakes in Terraform are silent and recurring. A wrong instance size or
a forgotten NAT gateway bills every hour until somebody reads an invoice, and
the diff that introduced it looked like one word.

### How to fix it

Check the resource types and sizes the finding names. The most common causes
are an oversized instance class copied from an example, a NAT gateway where a
gateway endpoint would do, and provisioned capacity left at a default.

### Accuracy

These are **estimates**, deliberately coarse: on-demand list prices, no
reserved instances, no savings plans, no data transfer, no per-request
charges. Treat a finding as a prompt to look, not as a quote. Set
`cost_impact_threshold_usd: 0` to switch the category off.

---

Custom rules defined in your own config get the category `custom:<id>` and are documented by whatever `message:` you give them.
