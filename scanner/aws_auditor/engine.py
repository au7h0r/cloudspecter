from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from scanner.risk import RiskFinding, RiskScoringEngine

from .models import AwsAuditFinding, AwsAuditReport, AwsAuditScope


logger = logging.getLogger(__name__)
risk_engine = RiskScoringEngine()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class AwsAuditorEngine:
    """Read-only AWS security posture auditor for authorized accounts."""

    def __init__(self, session: boto3.session.Session | None = None, logger_: logging.Logger | None = None) -> None:
        self.session = session or boto3.session.Session()
        self.logger = logger_ or logger

    def audit(
        self,
        region_name: str = "us-east-1",
        endpoint_url: str | None = None,
        source_label: str = "authorized_aws",
    ) -> AwsAuditReport:
        scope = AwsAuditScope(region=region_name, source=source_label, account_id=None)
        findings: list[AwsAuditFinding] = []
        notes: list[str] = ["Read-only audit only; no modifications performed."]

        try:
            sts = self.session.client("sts", region_name=region_name, endpoint_url=endpoint_url)
            scope.account_id = sts.get_caller_identity().get("Account")
        except Exception as exc:
            notes.append(f"sts_identity_lookup_failed: {exc}")
            self.logger.info("STS identity lookup failed: %s", exc)

        findings.extend(self._audit_imdsv1(region_name, endpoint_url))
        findings.extend(self._audit_public_s3(region_name, endpoint_url))
        findings.extend(self._audit_overprivileged_roles(region_name, endpoint_url))
        findings.extend(self._audit_open_security_groups(region_name, endpoint_url))
        findings.extend(self._audit_exposed_secrets(region_name, endpoint_url))
        findings.extend(self._audit_unencrypted_volumes(region_name, endpoint_url))

        counts = Counter(item.category for item in findings)
        score_payload = risk_engine.score_findings([item.finding for item in findings])
        risk_score = int(score_payload["score"])
        risk_level = str(score_payload["risk_level"])

        report = AwsAuditReport(
            generated_at=_now_iso(),
            scope=scope,
            findings=findings,
            counts={key: int(value) for key, value in counts.items()},
            risk_score=risk_score,
            risk_level=risk_level,
            remediation=self._remediation(findings),
            grafana=self._grafana_payload(scope, findings, risk_score),
            notes=notes,
        )
        return report

    def _client(self, service_name: str, region_name: str, endpoint_url: str | None):
        return self.session.client(service_name, region_name=region_name, endpoint_url=endpoint_url)

    def _audit_imdsv1(self, region_name: str, endpoint_url: str | None) -> list[AwsAuditFinding]:
        findings: list[AwsAuditFinding] = []
        try:
            ec2 = self._client("ec2", region_name, endpoint_url)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        metadata_options = instance.get("MetadataOptions", {})
                        http_tokens = str(metadata_options.get("HttpTokens", "optional")).lower()
                        if http_tokens != "required":
                            finding = risk_engine.from_code(
                                "imdsv1_enabled",
                                {
                                    "instance_id": instance.get("InstanceId"),
                                    "http_tokens": http_tokens,
                                    "http_endpoint": metadata_options.get("HttpEndpoint"),
                                },
                            )
                            findings.append(
                                AwsAuditFinding(
                                    category="imdsv1",
                                    resource_type="ec2_instance",
                                    resource_id=str(instance.get("InstanceId") or "unknown"),
                                    finding=finding,
                                    evidence={"metadata_options": metadata_options},
                                )
                            )
        except Exception as exc:
            self.logger.info("IMDS audit failed: %s", exc)
        return findings

    def _audit_public_s3(self, region_name: str, endpoint_url: str | None) -> list[AwsAuditFinding]:
        findings: list[AwsAuditFinding] = []
        try:
            s3 = self._client("s3", region_name, endpoint_url)
            for bucket in s3.list_buckets().get("Buckets", []):
                bucket_name = bucket.get("Name")
                public = False
                evidence: dict[str, Any] = {"bucket": bucket_name}
                try:
                    status = s3.get_bucket_policy_status(Bucket=bucket_name)
                    public = bool(status.get("PolicyStatus", {}).get("IsPublic"))
                    evidence["policy_status"] = status
                except Exception:
                    public = False
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    evidence["acl_grants"] = acl.get("Grants", [])
                    if any(grant.get("Grantee", {}).get("URI", "").endswith("AllUsers") for grant in acl.get("Grants", [])):
                        public = True
                except Exception:
                    pass
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    evidence["public_access_block"] = pab
                except Exception:
                    evidence["public_access_block"] = None
                if public:
                    findings.append(
                        AwsAuditFinding(
                            category="public_s3",
                            resource_type="s3_bucket",
                            resource_id=str(bucket_name),
                                finding=risk_engine.from_code("public_s3_bucket", {"public": True, "bucket": bucket_name}),
                            evidence=evidence,
                        )
                    )
        except Exception as exc:
            self.logger.info("S3 public access audit failed: %s", exc)
        return findings

    def _audit_overprivileged_roles(self, region_name: str, endpoint_url: str | None) -> list[AwsAuditFinding]:
        findings: list[AwsAuditFinding] = []
        try:
            iam = self._client("iam", region_name, endpoint_url)
            paginator = iam.get_paginator("list_roles")
            for page in paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role.get("RoleName")
                    evidence: dict[str, Any] = {"role_name": role_name}
                    broad = False
                    try:
                        attached = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                        evidence["attached_policies"] = attached
                        if any(policy.get("PolicyName") == "AdministratorAccess" for policy in attached):
                            broad = True
                    except Exception:
                        attached = []
                    try:
                        inline_names = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
                        evidence["inline_policy_names"] = inline_names
                        for policy_name in inline_names:
                            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name).get("PolicyDocument", {})
                            evidence.setdefault("inline_policies", []).append({"name": policy_name, "document": policy_doc})
                            if self._policy_is_broad(policy_doc):
                                broad = True
                    except Exception:
                        pass
                    if broad:
                        findings.append(
                            AwsAuditFinding(
                                category="overprivileged_iam_role",
                                resource_type="iam_role",
                                resource_id=str(role_name),
                                finding=risk_engine.from_code("overprivileged_iam_role", {"role_name": role_name, "overprivileged": True}),
                                evidence=evidence,
                            )
                        )
        except Exception as exc:
            self.logger.info("IAM role audit failed: %s", exc)
        return findings

    def _policy_is_broad(self, policy_doc: dict[str, Any]) -> bool:
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for statement in statements:
            effect = str(statement.get("Effect", "Allow"))
            action = statement.get("Action")
            resource = statement.get("Resource")
            if effect.lower() != "allow":
                continue
            if action in {"*", ["*"]} or resource in {"*", ["*"]}:
                return True
            if isinstance(action, list) and any(item == "*" or item.endswith(":*") for item in action):
                return True
            if isinstance(resource, list) and any(item == "*" for item in resource):
                return True
        return False

    def _audit_open_security_groups(self, region_name: str, endpoint_url: str | None) -> list[AwsAuditFinding]:
        findings: list[AwsAuditFinding] = []
        try:
            ec2 = self._client("ec2", region_name, endpoint_url)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for group in page.get("SecurityGroups", []):
                    group_id = group.get("GroupId")
                    open_rules = []
                    for permission in group.get("IpPermissions", []):
                        for ip_range in permission.get("IpRanges", []):
                            if ip_range.get("CidrIp") == "0.0.0.0/0":
                                open_rules.append({"protocol": permission.get("IpProtocol"), "from": permission.get("FromPort"), "to": permission.get("ToPort"), "cidr": "0.0.0.0/0"})
                        for ipv6_range in permission.get("Ipv6Ranges", []):
                            if ipv6_range.get("CidrIpv6") == "::/0":
                                open_rules.append({"protocol": permission.get("IpProtocol"), "from": permission.get("FromPort"), "to": permission.get("ToPort"), "cidr": "::/0"})
                    if open_rules:
                        findings.append(
                            AwsAuditFinding(
                                category="open_security_group",
                                resource_type="security_group",
                                resource_id=str(group_id),
                                finding=risk_engine.from_code("open_security_group", {"open_rules": open_rules, "group_id": group_id}),
                                evidence={"group_name": group.get("GroupName"), "open_rules": open_rules},
                            )
                        )
        except Exception as exc:
            self.logger.info("Security group audit failed: %s", exc)
        return findings

    def _audit_exposed_secrets(self, region_name: str, endpoint_url: str | None) -> list[AwsAuditFinding]:
        findings: list[AwsAuditFinding] = []
        try:
            secretsmanager = self._client("secretsmanager", region_name, endpoint_url)
            paginator = secretsmanager.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    secret_name = secret.get("Name")
                    evidence = {
                        "arn": secret.get("ARN"),
                        "rotation_enabled": secret.get("RotationEnabled"),
                        "kms_key_id": secret.get("KmsKeyId"),
                    }
                    if secret.get("RotationEnabled") is False or not secret.get("KmsKeyId"):
                        findings.append(
                            AwsAuditFinding(
                                category="exposed_secret",
                                resource_type="secret",
                                resource_id=str(secret_name),
                                finding=risk_engine.from_code("exposed_secret", {"secret_name": secret_name, **evidence}),
                                evidence=evidence,
                            )
                        )
        except Exception as exc:
            self.logger.info("Secrets audit failed: %s", exc)
        return findings

    def _audit_unencrypted_volumes(self, region_name: str, endpoint_url: str | None) -> list[AwsAuditFinding]:
        findings: list[AwsAuditFinding] = []
        try:
            ec2 = self._client("ec2", region_name, endpoint_url)
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    if not volume.get("Encrypted", False):
                        findings.append(
                            AwsAuditFinding(
                                category="unencrypted_volume",
                                resource_type="ebs_volume",
                                resource_id=str(volume.get("VolumeId")),
                                finding=risk_engine.from_code("unencrypted_volume", {"unencrypted": True, "volume_id": volume.get("VolumeId")}),
                                evidence={"encrypted": volume.get("Encrypted"), "size": volume.get("Size"), "state": volume.get("State")},
                            )
                        )
        except Exception as exc:
            self.logger.info("Volume audit failed: %s", exc)
        return findings

    def _remediation(self, findings: list[AwsAuditFinding]) -> list[str]:
        categories = {finding.category for finding in findings}
        remediation = [
            "Apply least-privilege IAM policies and review administrator-level access.",
            "Use AWS Config and Security Hub to keep public access and encryption misconfigurations visible.",
            "Keep IMDSv2 enforced on EC2 instances.",
        ]
        if "public_s3" in categories:
            remediation.append("Block public S3 access and verify bucket policies and ACLs.")
        if "open_security_group" in categories:
            remediation.append("Remove unrestricted ingress rules such as 0.0.0.0/0 and ::/0 for sensitive ports.")
        if "exposed_secret" in categories:
            remediation.append("Rotate secrets, enable rotation, and attach restrictive KMS and resource policies where applicable.")
        if "unencrypted_volume" in categories:
            remediation.append("Enable EBS encryption by default and re-create or snapshot/restore unencrypted volumes.")
        if "overprivileged_iam_role" in categories:
            remediation.append("Replace broad IAM permissions with service-scoped permissions.")
        if "imdsv1" in categories:
            remediation.append("Set EC2 metadata options to HttpTokens=required.")
        return remediation

    def _grafana_payload(self, scope: AwsAuditScope, findings: list[AwsAuditFinding], risk_score: int) -> dict[str, Any]:
        counts = Counter(item.category for item in findings)
        return {
            "metrics": [
                {"name": "cloudspecter_audit_findings_total", "value": len(findings), "labels": {"region": scope.region, "source": scope.source}},
                {"name": "cloudspecter_audit_public_s3_total", "value": counts.get("public_s3", 0), "labels": {"region": scope.region, "source": scope.source}},
                {"name": "cloudspecter_audit_imdsv1_total", "value": counts.get("imdsv1", 0), "labels": {"region": scope.region, "source": scope.source}},
                {"name": "cloudspecter_audit_open_sg_total", "value": counts.get("open_security_group", 0), "labels": {"region": scope.region, "source": scope.source}},
                {"name": "cloudspecter_audit_overprivileged_roles_total", "value": counts.get("overprivileged_iam_role", 0), "labels": {"region": scope.region, "source": scope.source}},
                {"name": "cloudspecter_audit_exposed_secrets_total", "value": counts.get("exposed_secret", 0), "labels": {"region": scope.region, "source": scope.source}},
                {"name": "cloudspecter_audit_unencrypted_volumes_total", "value": counts.get("unencrypted_volume", 0), "labels": {"region": scope.region, "source": scope.source}},
                {"name": "cloudspecter_audit_risk_score", "value": risk_score, "labels": {"region": scope.region, "source": scope.source}},
            ],
            "findings": [finding.to_dict() for finding in findings],
        }
