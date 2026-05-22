#!/usr/bin/env bash
set -euo pipefail

export AWS_DEFAULT_REGION=us-east-1

create_bucket() {
  local bucket_name="$1"
  awslocal s3api create-bucket --bucket "$bucket_name" >/dev/null 2>&1 || true
  printf 'CloudSpecter seed content for %s\n' "$bucket_name" | awslocal s3 cp - "s3://${bucket_name}/seed.txt" >/dev/null
}

create_user() {
  local user_name="$1"
  awslocal iam create-user --user-name "$user_name" >/dev/null 2>&1 || true
  awslocal iam create-access-key --user-name "$user_name" >/dev/null 2>&1 || true
}

create_secret() {
  local secret_name="$1"
  local secret_value="$2"
  awslocal secretsmanager create-secret --name "$secret_name" --secret-string "$secret_value" >/dev/null 2>&1 || true
}

create_table() {
  local table_name="$1"
  awslocal dynamodb create-table \
    --table-name "$table_name" \
    --attribute-definitions AttributeName=pk,AttributeType=S \
    --key-schema AttributeName=pk,KeyType=HASH \
    --billing-mode PAY_PER_REQUEST >/dev/null 2>&1 || true
}

for bucket in finance-data employee-records customer-backups internal-secrets; do
  create_bucket "$bucket"
done

for user in finance-auditor employee-analyst backup-operator security-reviewer; do
  create_user "$user"
done

create_secret "finance/db-password" "CloudSpecter-Finance-DB-Password-2026!"
create_secret "employee/onboarding-token" "CloudSpecter-Onboarding-Token-2026!"
create_secret "customer/backup-passphrase" "CloudSpecter-Backup-Passphrase-2026!"
create_secret "internal/secrets-master-key" "CloudSpecter-Master-Key-2026!"

for table in asset-inventory audit-events incident-triage credential-cache; do
  create_table "$table"
done
