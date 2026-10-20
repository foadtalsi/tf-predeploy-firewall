# Optional AWS read-only access

[Back to README](../README.md)

The core scan needs no cloud credentials. Enable `--cloud-read-access` only when you
want current AWS observations to adjust the findings whose risk depends on what a
resource holds: S3 `force_destroy`, `skip_final_snapshot`, ForceNew changes and
plan-confirmed destroys and replacements. This option is independent of paid plans.

## What changes

The scanner resolves the resource's literal name — a bucket's `bucket`, a database's
`identifier` or `cluster_identifier`, a table's or repository's `name` — and asks AWS
about that one resource. It does not look up a name it cannot resolve statically.
For a ForceNew change, the name comes from the base revision: it is the resource that
exists today, and the one the replacement destroys, even when the change renames it.
For a plan finding, the name comes from the plan's before-state, so it is known even
when the source builds it from a variable.

### What each lookup observes

| Resource type | AWS call | Observations |
|---|---|---|
| `aws_s3_bucket` | `s3:ListObjectsV2`, then `s3:ListObjectVersions` | absent, empty, holds objects |
| `aws_dynamodb_table` | `dynamodb:DescribeTable` | absent, holds items, exists |
| `aws_ecr_repository` | `ecr:ListImages` | absent, empty, holds images |
| `aws_db_instance` | `rds:DescribeDBInstances` | absent, exists |
| `aws_rds_cluster`, `aws_docdb_cluster`, `aws_neptune_cluster` | `rds:DescribeDBClusters` | absent, exists |
| `aws_redshift_cluster` | `redshift:DescribeClusters` | absent, exists |

A bucket with no current object is only empty once its version listing is empty too:
a versioned bucket can hold nothing but noncurrent versions, and `force_destroy`
deletes those. DynamoDB refreshes its item count about every six hours, so a count of
zero means "exists", not "empty". The scanner never reads object contents or table
items, and never connects to a database.

### `s3_force_destroy`

| Observation | Resulting severity |
|---|---|
| The bucket does not exist | `low` |
| The bucket is empty, including its versions | `low` |
| The bucket holds objects or versions | `critical` |
| Access is unavailable or the lookup cannot be interpreted | Original static severity |

### `skip_final_snapshot`

Applies to `aws_db_instance`, `aws_rds_cluster`, `aws_docdb_cluster`,
`aws_neptune_cluster` and `aws_redshift_cluster`.

| Observation | Resulting severity |
|---|---|
| The database does not exist | `low` |
| The database exists | `high` |
| Access is unavailable or the lookup cannot be interpreted | Original static severity |

A database that does not exist yet has nothing to lose; an existing one destroyed
without a final snapshot loses its data for good.

Both static severities are `medium`.

### `force_new_change` and `confirmed_replace`

Both describe a resource Terraform will destroy. Their static severity is `critical`
for stateful types and `high` otherwise; what the resource holds decides how much the
destroy costs.

| Observation | Resulting severity |
|---|---|
| The resource holds data | `critical` |
| The resource exists and is empty | `low` |
| The bucket does not exist | `low` |
| Any other resource type does not exist | Original static severity |
| The resource exists, contents unknown | Original static severity |
| Access is unavailable or the lookup cannot be interpreted | Original static severity |

S3 bucket names are global, so "no such bucket" is true everywhere. Every other type
is looked up in the runner's account and region only: absent there may mean it lives
in another region, which is why absence never lowers these two findings for them.
A ForceNew finding on a non-literal value stays `low` and is not looked up.

A low result describes the current observation; it does not guarantee that a later
deletion is safe. Review the finding and Terraform plan before changing
infrastructure.

## Allowed operations

| AWS API operation | Purpose |
|---|---|
| `sts:GetCallerIdentity` | Check access and identify the account |
| `s3:ListObjectsV2` | Check bucket existence and whether it contains objects |
| `s3:ListObjectVersions` | Check whether a bucket with no current object still holds versions |
| `rds:DescribeDBInstances` | Check whether a DB instance exists |
| `rds:DescribeDBClusters` | Check whether an RDS, DocumentDB or Neptune cluster exists |
| `dynamodb:DescribeTable` | Check whether a table exists and its item count |
| `ecr:ListImages` | Check whether a repository exists and holds images |
| `redshift:DescribeClusters` | Check whether a Redshift cluster exists |

`_READ_ONLY_OPERATIONS` in `src/tfpdf/cloudread.py` is enforced by a botocore handler
on boto3's default session. Other operations are rejected before request parameters
are built, including `GetObject` and write/delete operations. Listings return object
names; the scanner does not read object contents. Describe calls return database
metadata; the scanner never connects to a database.

An access failure preserves static scanning. The CLI prints whether access opened
and, if it did not, why. Individual lookup failures leave the original severity.

## Permissions and GitHub setup

An example role policy permits bucket listing and database descriptions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "TFPreDeployFirewallReadOnly",
      "Effect": "Allow",
      "Action": ["s3:ListBucket", "s3:ListBucketVersions"],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "TFPreDeployFirewallReadOnlyDatabases",
      "Effect": "Allow",
      "Action": ["rds:DescribeDBInstances", "rds:DescribeDBClusters"],
      "Resource": ["arn:aws:rds:*:*:db:*", "arn:aws:rds:*:*:cluster:*"]
    },
    {
      "Sid": "TFPreDeployFirewallReadOnlyTables",
      "Effect": "Allow",
      "Action": ["dynamodb:DescribeTable"],
      "Resource": "arn:aws:dynamodb:*:*:table/*"
    },
    {
      "Sid": "TFPreDeployFirewallReadOnlyRepositories",
      "Effect": "Allow",
      "Action": ["ecr:ListImages"],
      "Resource": "arn:aws:ecr:*:*:repository/*"
    },
    {
      "Sid": "TFPreDeployFirewallReadOnlyWarehouses",
      "Effect": "Allow",
      "Action": ["redshift:DescribeClusters"],
      "Resource": "*"
    }
  ]
}
```

Narrow the resource lists to the buckets and databases you want inspected. Leave out
a statement to skip that check: a refused lookup keeps the static severity. This
policy does not configure who can assume the role; configure its OIDC trust for your
repository separately. The scanner needs neither `s3:GetObject` nor write permissions.

Configure AWS credentials before the scanner step:

```yaml
permissions:
  id-token: write
  contents: read
  pull-requests: write

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

Use a role and region appropriate for your environment. Check the scanner's stderr
message to verify that access was enabled. Unsupported or failed lookups retain
static severity rather than proving that a resource is absent.

## Local CLI setup

The Action image includes boto3. For a local installation, request the optional extra:

```sh
pip install "tf-predeploy-firewall[aws] @ git+https://github.com/foadtalsi/tf-predeploy-firewall@v1"
export AWS_REGION=eu-west-3
tf-predeploy-firewall --uncommitted --cloud-read-access
```

Credentials use the standard boto3 chain, such as environment variables or an AWS
profile. Set `AWS_REGION` or `AWS_DEFAULT_REGION` explicitly; without a region, the
option reports that it cannot open access. `TFPDF_CLOUD_READ_ACCESS=true` also enables
it. When disabled, this integration reads no credentials and makes no AWS requests.
