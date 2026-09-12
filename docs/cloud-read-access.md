# Optional AWS read-only access

[Back to README](../README.md)

The core scan needs no cloud credentials. Enable `--cloud-read-access` only when you
want current AWS observations to adjust S3 `force_destroy` findings. This option is
independent of paid plans.

## What changes

The scanner resolves a bucket's literal name and checks whether it exists and has
objects. It does not look up a name it cannot resolve statically.

| Observation | Resulting severity |
|---|---|
| S3 returns `NoSuchBucket` | `low` |
| Bucket listing is empty | `low` |
| Bucket listing contains objects | `critical` |
| Access is unavailable or the lookup cannot be interpreted | Original static severity |

The static `s3_force_destroy` severity is `medium`. A low result describes the current
observation; it does not guarantee that a later deletion is safe. Review the finding
and Terraform plan before changing infrastructure.

## Allowed operations

| AWS API operation | Purpose |
|---|---|
| `sts:GetCallerIdentity` | Check access and identify the account |
| `s3:ListObjectsV2` | Check bucket existence and whether it contains objects |

`_READ_ONLY_OPERATIONS` in `src/tfpdf/cloudread.py` is enforced by a botocore handler
on boto3's default session. Other operations are rejected before request parameters
are built, including `GetObject` and write/delete operations. Listings return object
names; the scanner does not read object contents.

An access failure preserves static scanning. The CLI prints whether access opened
and, if it did not, why. Individual lookup failures leave the original severity.

## Permissions and GitHub setup

An example role policy permits bucket listing:

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

Narrow the resource list to the buckets you want inspected. This policy does not
configure who can assume the role; configure its OIDC trust for your repository
separately. The scanner needs neither `s3:GetObject` nor write permissions.

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
static severity rather than proving that a bucket is absent.

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
