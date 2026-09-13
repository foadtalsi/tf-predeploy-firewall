# Optional AWS read-only access

[Back to README](../README.md)

The core scan needs no cloud credentials. Enable `--cloud-read-access` only when you
want current AWS observations to adjust S3 `force_destroy` and RDS
`skip_final_snapshot` findings. This option is independent of paid plans.

## What changes

The scanner resolves the resource's literal name — a bucket's `bucket`, a database's
`identifier` or `cluster_identifier` — and asks AWS about that one resource. It does
not look up a name it cannot resolve statically.

For `s3_force_destroy`:

| Observation | Resulting severity |
|---|---|
| S3 returns `NoSuchBucket` | `low` |
| Bucket listing is empty | `low` |
| Bucket listing contains objects | `critical` |
| Access is unavailable or the lookup cannot be interpreted | Original static severity |

For `skip_final_snapshot` on `aws_db_instance` and `aws_rds_cluster`:

| Observation | Resulting severity |
|---|---|
| RDS returns `DBInstanceNotFound` or `DBClusterNotFoundFault` | `low` |
| The database exists | `critical` |
| Access is unavailable or the lookup cannot be interpreted | Original static severity |

A database that does not exist yet has nothing to lose; an existing one destroyed
without a final snapshot loses its data for good. Other resource types covered by
`skip_final_snapshot` keep their static severity.

Both static severities are `medium`. A low result describes the current observation;
it does not guarantee that a later deletion is safe. Review the finding and Terraform
plan before changing infrastructure.

## Allowed operations

| AWS API operation | Purpose |
|---|---|
| `sts:GetCallerIdentity` | Check access and identify the account |
| `s3:ListObjectsV2` | Check bucket existence and whether it contains objects |
| `rds:DescribeDBInstances` | Check whether a DB instance exists |
| `rds:DescribeDBClusters` | Check whether a DB cluster exists |

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
      "Action": ["s3:ListBucket"],
      "Resource": "arn:aws:s3:::*"
    },
    {
      "Sid": "TFPreDeployFirewallReadOnlyDatabases",
      "Effect": "Allow",
      "Action": ["rds:DescribeDBInstances", "rds:DescribeDBClusters"],
      "Resource": ["arn:aws:rds:*:*:db:*", "arn:aws:rds:*:*:cluster:*"]
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
