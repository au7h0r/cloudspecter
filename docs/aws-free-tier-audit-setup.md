# CloudSpecter AWS Free Tier Audit Setup

Use this only for your own AWS account or another environment you are explicitly authorized to audit.

## 1. Create a least-privilege audit identity

Create a dedicated IAM user or role for the audit with read-only permissions only. A practical start is AWS managed `ReadOnlyAccess`, then trim it down if you want to be stricter.

Recommended permissions for the audit profile:

- `ec2:Describe*`
- `s3:ListAllMyBuckets`
- `s3:GetBucketAcl`
- `s3:GetBucketPolicyStatus`
- `s3:GetPublicAccessBlock`
- `iam:List*`
- `iam:Get*`
- `secretsmanager:ListSecrets`
- `secretsmanager:GetResourcePolicy`
- `ec2:DescribeVolumes`
- `ec2:DescribeSecurityGroups`
- `sts:GetCallerIdentity`

## 2. Configure the AWS CLI profile

Run:

```powershell
aws configure --profile cloudspecter-audit
```

Then verify the identity:

```powershell
aws sts get-caller-identity --profile cloudspecter-audit
```

## 3. Keep the account safe

- Enable MFA on the audit identity.
- Set an AWS Budget and billing alarm before running anything.
- Keep the account to free-tier resources such as `t2.micro` where possible.
- Avoid write permissions unless you are explicitly testing remediation.

## 4. Run the audit

From the repository root:

```powershell
python -m scanner.cli audit --region us-east-1 --output-dir artifacts/reports
```

If you are auditing LocalStack instead of real AWS, pass the local endpoint:

```powershell
python -m scanner.cli audit --region us-east-1 --endpoint-url http://localhost:4566 --output-dir artifacts/reports
```

## 5. Interpret the findings

Look for these categories first:

- `IMDSv1 enabled` with severity `Critical`
- `Public S3 bucket` with severity `Critical`
- `Overprivileged IAM role` with severity `High`
- `Open security group` with severity `High`
- `Exposed secret` with severity `Critical`
- `Unencrypted volume` with severity `Medium`

## 6. Deliverables

The audit creates both JSON and Markdown reports in `artifacts/reports/`.
