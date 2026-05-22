from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote

import boto3
import requests


IMDS_PATHS = [
    "/latest/meta-data/",
    "/latest/meta-data/iam/",
    "/latest/meta-data/iam/security-credentials/",
]


@dataclass
class ValidationResult:
    target_url: str
    reachable: bool
    status_code: int | None
    evidence: str
    finding: str


@dataclass
class ImdsDetectionResult:
    endpoint: str
    token_required: bool
    token_endpoint_available: bool
    metadata_reachable_without_token: bool
    credentials_reachable_with_token: bool


@dataclass
class PostureSummary:
    account_id: str | None
    region: str
    s3_buckets: list[str]
    iam_users: list[str]
    dynamodb_tables: list[str]
    secrets: list[str]
    source: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def safe_ssrf_validation(base_url: str, timeout_seconds: int = 5) -> list[ValidationResult]:
    """Validate whether a fetch endpoint can reach local metadata-style paths.

    This is intentionally limited to lab-owned or otherwise authorized environments.
    """

    base_url = base_url.rstrip("/")
    results: list[ValidationResult] = []
    test_targets = [
        f"{base_url}/api/fetch?url={quote(f'{base_url}/health', safe=':/?&=%')}",
        f"{base_url}/api/fetch?url={quote(f'{base_url}/latest/meta-data/', safe=':/?&=%')}",
    ]

    for target in test_targets:
        try:
            response = requests.get(target, timeout=timeout_seconds)
            text = response.text[:300]
            is_metadata_like = "iam" in text.lower() or "security-credentials" in text.lower()
            results.append(
                ValidationResult(
                    target_url=target,
                    reachable=response.ok,
                    status_code=response.status_code,
                    evidence=text,
                    finding=("possible_ssrf" if is_metadata_like else "normal_fetch"),
                )
            )
        except requests.RequestException as exc:
            results.append(
                ValidationResult(
                    target_url=target,
                    reachable=False,
                    status_code=None,
                    evidence=str(exc),
                    finding="unreachable",
                )
            )

    return results


def detect_imds_mode(endpoint: str, timeout_seconds: int = 5) -> ImdsDetectionResult:
    """Detect whether an IMDS endpoint behaves like IMDSv1 or IMDSv2."""

    endpoint = endpoint.rstrip("/")
    token_url = f"{endpoint}/latest/api/token"
    metadata_root = f"{endpoint}/latest/meta-data/"
    credentials_url = f"{endpoint}/latest/meta-data/iam/security-credentials/CloudSpecterLabRole"

    token_endpoint_available = False
    metadata_reachable_without_token = False
    credentials_reachable_with_token = False
    token_required = False

    try:
        token_response = requests.put(
            token_url,
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"},
            timeout=timeout_seconds,
        )
        token_endpoint_available = token_response.ok and bool(token_response.text.strip())
        token = token_response.text.strip() if token_endpoint_available else None
    except requests.RequestException:
        token = None

    try:
        metadata_response = requests.get(metadata_root, timeout=timeout_seconds)
        metadata_reachable_without_token = metadata_response.ok
        token_required = metadata_response.status_code == 401
    except requests.RequestException:
        metadata_response = None

    if token:
        try:
            credentials_response = requests.get(
                credentials_url,
                headers={"X-aws-ec2-metadata-token": token},
                timeout=timeout_seconds,
            )
            credentials_reachable_with_token = credentials_response.ok
        except requests.RequestException:
            credentials_reachable_with_token = False

    return ImdsDetectionResult(
        endpoint=endpoint,
        token_required=token_required,
        token_endpoint_available=token_endpoint_available,
        metadata_reachable_without_token=metadata_reachable_without_token,
        credentials_reachable_with_token=credentials_reachable_with_token,
    )


def audit_authorized_aws_account(
    region_name: str = "us-east-1",
    endpoint_url: str | None = None,
) -> PostureSummary:
    """Audit a permitted AWS account or a LocalStack environment for basic resources."""

    session = boto3.session.Session(region_name=region_name)
    s3 = session.client("s3", endpoint_url=endpoint_url)
    iam = session.client("iam", endpoint_url=endpoint_url)
    dynamodb = session.client("dynamodb", endpoint_url=endpoint_url)
    secretsmanager = session.client("secretsmanager", endpoint_url=endpoint_url)

    account_id: str | None = None
    source = "aws"
    try:
        sts = session.client("sts", endpoint_url=endpoint_url)
        account_id = sts.get_caller_identity().get("Account")
    except Exception:
        source = "localstack_or_unavailable"

    buckets = sorted(bucket["Name"] for bucket in s3.list_buckets().get("Buckets", []))
    users = sorted(user["UserName"] for user in iam.list_users().get("Users", []))
    tables = sorted(dynamodb.list_tables().get("TableNames", []))

    secret_names: list[str] = []
    try:
        secret_names = sorted(secret["Name"] for secret in secretsmanager.list_secrets().get("SecretList", []))
    except Exception:
        secret_names = []

    return PostureSummary(
        account_id=account_id,
        region=region_name,
        s3_buckets=buckets,
        iam_users=users,
        dynamodb_tables=tables,
        secrets=secret_names,
        source=source,
    )


def build_comparison_report(
    vulnerable_validation: Iterable[ValidationResult],
    protected_validation: Iterable[ValidationResult],
    vulnerable_imds: ImdsDetectionResult,
    protected_imds: ImdsDetectionResult,
    posture: PostureSummary,
) -> dict[str, Any]:
    return {
        "generated_at": _now_iso(),
        "summary": {
            "lab_type": "defensive_ssrf_imds_assessment",
            "source": posture.source,
            "region": posture.region,
        },
        "comparison": {
            "vulnerable_environment": {
                "ssrf_validation": [asdict(item) for item in vulnerable_validation],
                "imds": asdict(vulnerable_imds),
            },
            "protected_environment": {
                "ssrf_validation": [asdict(item) for item in protected_validation],
                "imds": asdict(protected_imds),
            },
        },
        "posture": asdict(posture),
        "remediation": [
            "Require IMDSv2 tokens on instance metadata access",
            "Restrict outbound fetchers to an allowlist or proxy",
            "Monitor metadata request counters and unexpected SSRF indicators",
            "Limit IAM permissions on any instance profiles used in the lab",
        ],
    }


def save_report(report: dict[str, Any], output_path: str | Path) -> Path:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return output_file
