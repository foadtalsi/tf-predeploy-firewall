<!-- tf-predeploy-firewall:report -->
## TF Pre-Deploy Firewall

🚫 **Merge blocked** — findings at or above `critical` severity (threshold: `high`).

| Severity | File | Line | Category | Resource | Detail |
|---|---|---|---|---|---|
| 🔵 low | `main.tf` | 1 | Custom rule: no-iam-users | `aws_iam_user.bob` | Use aws_iam_role instead |
| 🔴 critical | `rds.tf` | 12 | Tutorial-copy pattern | [`aws_db_instance.prod`](https://registry.terraform.io/providers/hashicorp/aws/5.31.0/docs/resources/db_instance) | password = "hunter2" — hardcoded credential (a & b < c > d) |
| 🟠 high | `s3.tf` | 3 | Reachable from the internet | `aws_s3_bucket_public_access_block.logs` | block_public_acls = false — bucket ACLs may grant public read |

### Suggested fixes

<details><summary><code>aws_s3_bucket_public_access_block.logs</code> (s3.tf:3)</summary>

```hcl
block_public_acls = true
block_public_policy = true
```

</details>


<details><summary>1 accepted finding(s) — excluded from the block decision</summary>

| Severity | File | Line | Category | Resource | Detail | Accepted because |
|---|---|---|---|---|---|---|
| 🟡 medium | `iam.tf` | 40 | Missing prevent_destroy | `aws_db_instance.legacy` | no prevent_destroy guard | legacy repo, ticketed as INFRA-42 |

</details>
