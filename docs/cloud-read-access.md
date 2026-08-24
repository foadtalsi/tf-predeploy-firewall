# Optional read-only cloud access

**The scanner needs no credentials, and that does not change.** Everything it
detects by default it detects from the `.tf` files in the pull request, read
against a provider schema it already carries. Nothing on this page is required
to use it.

What this page describes is one option you can turn on, `cloud-read-access`,
and exactly what it costs you to turn it on.

## The one thing the repository cannot tell us

These two resources are the same eleven characters of HCL:

```hcl
resource "aws_s3_bucket" "scratch" {
  bucket        = "ci-scratch-2026"
  force_destroy = true          # a bucket this PR invents. Harmless.
}

resource "aws_s3_bucket" "backups" {
  bucket        = "acme-prod-backups"
  force_destroy = true          # eleven years of backups. Not harmless.
}
```

`force_destroy = true` removes the guard that makes a `terraform destroy` fail
on a non-empty bucket. On the first resource that guard was protecting nothing.
On the second it is the last thing between a mistaken apply and permanent loss.

Nothing in the repository distinguishes them, so the static rule has to score
both the same — medium, which is too loud for the first and far too quiet for
the second. One read-only lookup separates them.

## What it does with the access

With `cloud-read-access: "true"` the scanner asks three questions and stops:

| Call | What it answers |
|---|---|
| `sts:GetCallerIdentity` | which account these credentials reach, so the report can name it |
| `s3:ListObjectsV2` | does this bucket exist, and does it hold anything |

That is the whole list. It is not a summary of a longer one: the allow-list
lives in `_READ_ONLY_OPERATIONS` in `tfpdf/cloudread.py`, a botocore handler
refuses any call absent from it before the request is built, and the line the
scanner prints in your CI log is generated from that same table. An operation
that is not there cannot be made, including by a future version that forgets to
update this page.

Note what is missing: **`s3:GetObject` is not on the list, and the IAM policy
below does not grant it.** The scanner can learn that a bucket is not empty and
cannot read a single object in it — the listing returns key names, and the only
thing done with them is counting whether there is at least one.

The effect on the report:

| What the account says | `force_destroy = true` scores |
|---|---|
| no such bucket — this PR creates it | **low**, with that stated in the finding |
| the bucket exists but is empty today | **low** |
| the bucket exists and holds objects | **high** |
| anything unreadable — no credentials, refused, API down | **unchanged**, silently |

Every changed severity says in its own message what was seen and in which
account. A number that moved without saying why is worse than one that did not
move.

## The IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TFPreDeployFirewallReadOnly",
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::*"
    }
  ]
}
```

`s3:ListBucket` is the permission behind `ListObjectsV2` — it grants listing
the *names* in a bucket, not reading their contents. `sts:GetCallerIdentity`
needs no permission at all; every set of credentials can call it.

**One limitation, stated plainly:** buckets are queried in the region the
workflow configured. A bucket that lives in another region answers with a
redirect the scan treats as "unknown", so its severity is left alone. That is
the safe direction to be wrong in, but it does mean a multi-region estate gets
the benefit only in its main region.
Narrow `Resource` to the buckets you want looked at if you would rather.
Anything the policy refuses reads as "unknown" and leaves the severity alone,
so a policy that is too tight degrades the option rather than breaking the
scan.

## Wiring it up

Use OIDC. It means no long-lived access key exists to leak, and the role can
only be assumed by a workflow run in your repository.

```yaml
permissions:
  id-token: write        # for OIDC
  contents: read
  pull-requests: write   # for the PR comment

steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0

  - uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: arn:aws:iam::123456789012:role/tf-predeploy-firewall-read
      aws-region: eu-west-3

  - uses: foadtalsi/tf-predeploy-firewall@v1
    with:
      cloud-read-access: "true"
```

The order matters: `configure-aws-credentials` exports the credentials into the
job environment, and the scanner's container inherits them from there. Put it
after the scanner and the scanner finds nothing — which, being fail-open, looks
like the option doing nothing rather than an error, so check the log line
described below.

`aws-region` is not optional — it is where the lookups go, and without it the
option reports that it is switching itself off.

## Telling whether it is on

The scanner prints one line to stderr on every run where the option is set:

```
cloud read access active on account 123456789012 in eu-west-3
  (read-only: s3:ListObjectsV2, sts:GetCallerIdentity)
```

or, when it could not open the access, the reason:

```
cloud read access requested but no usable credentials were found
  (NoCredentialsError) — the scan continues without it
```

There is no third possibility where severities changed and nothing was printed.

## What happens if you never turn it on

The default. No credentials are read, no request leaves the runner, and every
rule scores exactly as it did before this option existed. The `boto3` that
makes the lookups possible is an extra (`pip install
"tf-predeploy-firewall[aws]"`) rather than a dependency; the published Action
image carries it so that turning the flag on is a one-line change, and it sits
unused otherwise.

## Running it outside GitHub Actions

```
tf-predeploy-firewall --cloud-read-access
```

or set `TFPDF_CLOUD_READ_ACCESS=true`. Credentials come from the standard boto3
chain — environment, profile, instance role. Region comes from `AWS_REGION` or
`AWS_DEFAULT_REGION`; without one the option reports that and switches itself
off.
