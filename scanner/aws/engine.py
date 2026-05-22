from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .models import AwsEnumerationReport, AwsResourceInventory
from scanner.risk import RiskFinding, RiskScoringEngine


logger = logging.getLogger(__name__)
risk_engine = RiskScoringEngine()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _clamp_score(score: int) -> int:
    return max(0, min(100, score))


class AwsEnumerationEngine:
    def __init__(self, session: boto3.session.Session | None = None, logger_: logging.Logger | None = None) -> None:
        self.session = session or boto3.session.Session()
        self.logger = logger_ or logger

    def enumerate(
        self,
        region_name: str = "us-east-1",
        endpoint_url: str | None = None,
        source_label: str = "authorized_aws",
    ) -> AwsEnumerationReport:
        inventory = AwsResourceInventory(account_id=None, region=region_name, source=source_label)
        errors: list[str] = []

        try:
            sts = self.session.client("sts", region_name=region_name, endpoint_url=endpoint_url)
            inventory.account_id = sts.get_caller_identity().get("Account")
        except (ClientError, BotoCoreError, Exception) as exc:
            errors.append(f"sts: {exc}")
            self.logger.info("STS identity lookup failed: %s", exc)

        inventory.s3_buckets = self._collect_s3(region_name, endpoint_url)
        inventory.ec2_instances = self._collect_ec2(region_name, endpoint_url)
        inventory.lambda_functions = self._collect_lambda(region_name, endpoint_url)
        inventory.iam_users, inventory.iam_roles = self._collect_iam(region_name, endpoint_url)
        inventory.secrets = self._collect_secrets(region_name, endpoint_url)

        counts = {
            "s3_buckets": len(inventory.s3_buckets),
            "ec2_instances": len(inventory.ec2_instances),
            "lambda_functions": len(inventory.lambda_functions),
            "iam_users": len(inventory.iam_users),
            "iam_roles": len(inventory.iam_roles),
            "secrets": len(inventory.secrets),
        }
        findings = self._build_findings(counts)
        score_payload = risk_engine.score_findings(findings)
        risk_score = int(score_payload["score"])

        report = AwsEnumerationReport(
            generated_at=_now_iso(),
            inventory=inventory,
            counts=counts,
            risk_score=risk_score,
            risk_level=str(score_payload["risk_level"]),
            remediation=self._remediation(counts),
            findings=findings,
            grafana=self._grafana_payload(inventory, counts, risk_score),
            notes=errors or ["Authorized enumeration only; no write operations performed."],
        )
        return report

    def _paginate(self, client: Any, operation_name: str, result_key: str) -> list[dict[str, Any]]:
        try:
            paginator = client.get_paginator(operation_name)
        except Exception:
            paginator = None

        items: list[dict[str, Any]] = []
        if paginator is None:
            response = getattr(client, operation_name)(**{})
            raw_items = response.get(result_key, [])
            return list(raw_items)

        for page in paginator.paginate():
            items.extend(page.get(result_key, []))
        return items

    def _collect_s3(self, region_name: str, endpoint_url: str | None) -> list[dict[str, Any]]:
        try:
            client = self.session.client("s3", region_name=region_name, endpoint_url=endpoint_url)
            buckets = []
            for bucket in client.list_buckets().get("Buckets", []):
                bucket_name = bucket.get("Name")
                location = None
                try:
                    location = client.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
                except Exception:
                    location = None
                buckets.append(
                    {
                        "name": bucket_name,
                        "creation_date": str(bucket.get("CreationDate")),
                        "location": location,
                    }
                )
            return buckets
        except (ClientError, BotoCoreError, Exception) as exc:
            self.logger.info("S3 enumeration failed: %s", exc)
            return []

    def _collect_ec2(self, region_name: str, endpoint_url: str | None) -> list[dict[str, Any]]:
        try:
            client = self.session.client("ec2", region_name=region_name, endpoint_url=endpoint_url)
            instances: list[dict[str, Any]] = []
            try:
                paginator = client.get_paginator("describe_instances")
                pages = paginator.paginate()
                reservations = []
                for page in pages:
                    reservations.extend(page.get("Reservations", []))
            except Exception:
                reservations = client.describe_instances().get("Reservations", [])

            for reservation in reservations:
                for instance in reservation.get("Instances", []):
                    instances.append(
                        {
                            "instance_id": instance.get("InstanceId"),
                            "state": instance.get("State", {}).get("Name"),
                            "instance_type": instance.get("InstanceType"),
                            "public_ip": instance.get("PublicIpAddress"),
                            "private_ip": instance.get("PrivateIpAddress"),
                            "tags": instance.get("Tags", []),
                        }
                    )
            return instances
        except (ClientError, BotoCoreError, Exception) as exc:
            self.logger.info("EC2 enumeration failed: %s", exc)
            return []

    def _collect_lambda(self, region_name: str, endpoint_url: str | None) -> list[dict[str, Any]]:
        try:
            client = self.session.client("lambda", region_name=region_name, endpoint_url=endpoint_url)
            functions: list[dict[str, Any]] = []
            try:
                paginator = client.get_paginator("list_functions")
                pages = paginator.paginate()
                lambda_functions = []
                for page in pages:
                    lambda_functions.extend(page.get("Functions", []))
            except Exception:
                lambda_functions = client.list_functions().get("Functions", [])

            for function in lambda_functions:
                functions.append(
                    {
                        "name": function.get("FunctionName"),
                        "runtime": function.get("Runtime"),
                        "handler": function.get("Handler"),
                        "last_modified": function.get("LastModified"),
                        "code_size": function.get("CodeSize"),
                        "version": function.get("Version"),
                    }
                )
            return functions
        except (ClientError, BotoCoreError, Exception) as exc:
            self.logger.info("Lambda enumeration failed: %s", exc)
            return []

    def _collect_iam(self, region_name: str, endpoint_url: str | None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        try:
            client = self.session.client("iam", region_name=region_name, endpoint_url=endpoint_url)
            users = []
            roles = []
            try:
                paginator = client.get_paginator("list_users")
                user_items = []
                for page in paginator.paginate():
                    user_items.extend(page.get("Users", []))
            except Exception:
                user_items = client.list_users().get("Users", [])

            try:
                paginator = client.get_paginator("list_roles")
                role_items = []
                for page in paginator.paginate():
                    role_items.extend(page.get("Roles", []))
            except Exception:
                role_items = client.list_roles().get("Roles", [])

            for item in user_items:
                users.append(
                    {
                        "user_name": item.get("UserName"),
                        "user_id": item.get("UserId"),
                        "arn": item.get("Arn"),
                        "create_date": str(item.get("CreateDate")),
                    }
                )
            for item in role_items:
                roles.append(
                    {
                        "role_name": item.get("RoleName"),
                        "role_id": item.get("RoleId"),
                        "arn": item.get("Arn"),
                        "create_date": str(item.get("CreateDate")),
                    }
                )
            return users, roles
        except (ClientError, BotoCoreError, Exception) as exc:
            self.logger.info("IAM enumeration failed: %s", exc)
            return [], []

    def _collect_secrets(self, region_name: str, endpoint_url: str | None) -> list[dict[str, Any]]:
        try:
            client = self.session.client("secretsmanager", region_name=region_name, endpoint_url=endpoint_url)
            secrets: list[dict[str, Any]] = []
            try:
                paginator = client.get_paginator("list_secrets")
                secret_items = []
                for page in paginator.paginate():
                    secret_items.extend(page.get("SecretList", []))
            except Exception:
                secret_items = client.list_secrets().get("SecretList", [])

            for item in secret_items:
                secrets.append(
                    {
                        "name": item.get("Name"),
                        "arn": item.get("ARN"),
                        "description": item.get("Description"),
                        "last_changed_date": str(item.get("LastChangedDate")),
                        "rotation_enabled": item.get("RotationEnabled"),
                    }
                )
            return secrets
        except (ClientError, BotoCoreError, Exception) as exc:
            self.logger.info("Secrets Manager enumeration failed: %s", exc)
            return []

    def _risk_score(self, counts: dict[str, int], account_id: str | None) -> int:
        score = 10
        score += min(20, counts["s3_buckets"] * 3)
        score += min(20, counts["ec2_instances"] * 2)
        score += min(20, counts["lambda_functions"] * 2)
        score += min(20, counts["iam_users"] * 2)
        score += min(15, counts["iam_roles"])
        score += min(15, counts["secrets"] * 2)
        if account_id:
            score += 5
        return _clamp_score(score)

    def _build_findings(self, counts: dict[str, int]) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        if counts["s3_buckets"]:
            findings.append(risk_engine.from_code("s3_inventory", {"count": counts["s3_buckets"]}))
        if counts["ec2_instances"]:
            findings.append(risk_engine.from_code("ec2_inventory", {"count": counts["ec2_instances"]}))
        if counts["lambda_functions"]:
            findings.append(risk_engine.from_code("lambda_inventory", {"count": counts["lambda_functions"]}))
        if counts["iam_users"] or counts["iam_roles"]:
            findings.append(risk_engine.from_code("iam_inventory", {"users": counts["iam_users"], "roles": counts["iam_roles"]}))
        if counts["secrets"]:
            findings.append(risk_engine.from_code("secrets_inventory", {"count": counts["secrets"]}))
        return findings

    def _remediation(self, counts: dict[str, int]) -> list[str]:
        recommendations = [
            "Review IAM permissions and apply least-privilege policies.",
            "Enable CloudTrail and alert on changes to IAM, S3, Lambda, and Secrets Manager.",
            "Periodically inventory secrets and remove unused credentials.",
        ]
        if counts["secrets"]:
            recommendations.append("Consider rotating secrets discovered during authorized enumeration.")
        if counts["s3_buckets"]:
            recommendations.append("Validate S3 bucket policies and public access settings.")
        return recommendations

    def _grafana_payload(self, inventory: AwsResourceInventory, counts: dict[str, int], risk_score: int) -> dict[str, Any]:
        return {
            "metrics": [
                {"name": "cloudspecter_aws_s3_buckets_total", "value": counts["s3_buckets"], "labels": {"region": inventory.region, "source": inventory.source}},
                {"name": "cloudspecter_aws_ec2_instances_total", "value": counts["ec2_instances"], "labels": {"region": inventory.region, "source": inventory.source}},
                {"name": "cloudspecter_aws_lambda_functions_total", "value": counts["lambda_functions"], "labels": {"region": inventory.region, "source": inventory.source}},
                {"name": "cloudspecter_aws_iam_users_total", "value": counts["iam_users"], "labels": {"region": inventory.region, "source": inventory.source}},
                {"name": "cloudspecter_aws_iam_roles_total", "value": counts["iam_roles"], "labels": {"region": inventory.region, "source": inventory.source}},
                {"name": "cloudspecter_aws_secrets_total", "value": counts["secrets"], "labels": {"region": inventory.region, "source": inventory.source}},
                {"name": "cloudspecter_aws_risk_score", "value": risk_score, "labels": {"region": inventory.region, "source": inventory.source}},
            ],
            "inventory_snapshot": inventory.to_dict(),
        }
