from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any


@dataclass(frozen=True)
class RiskFinding:
    finding: str
    severity: str
    cvss: float
    exploitability: str
    mitre: str
    description: str = ""
    evidence: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RiskScoringEngine:
    """Standardize findings for posture assessment reports."""

    def __init__(self) -> None:
        self._catalog = {
            "imdsv1_enabled": {
                "finding": "IMDSv1 enabled",
                "severity": "Critical",
                "cvss": 9.1,
                "exploitability": "High",
                "mitre": "T1552.005",
                "description": "Instance metadata can be queried without token enforcement.",
            },
            "imdsv2_required": {
                "finding": "IMDSv2 enforced",
                "severity": "Info",
                "cvss": 0.0,
                "exploitability": "Low",
                "mitre": "T1552.005",
                "description": "Token-based metadata access reduces SSRF abuse exposure.",
            },
            "metadata_reachable": {
                "finding": "Metadata endpoint reachable",
                "severity": "High",
                "cvss": 8.2,
                "exploitability": "High",
                "mitre": "T1552.005",
                "description": "The metadata endpoint is accessible from the assessed path.",
            },
            "blocked_metadata_access": {
                "finding": "Blocked metadata access attempts observed",
                "severity": "Medium",
                "cvss": 4.3,
                "exploitability": "Low",
                "mitre": "T1552.005",
                "description": "Protected mode prevented unauthorized metadata access.",
            },
            "s3_inventory": {
                "finding": "S3 buckets discovered",
                "severity": "Medium",
                "cvss": 5.0,
                "exploitability": "Medium",
                "mitre": "T1530",
                "description": "Storage inventory discovered during authorized enumeration.",
            },
            "ec2_inventory": {
                "finding": "EC2 instances discovered",
                "severity": "Low",
                "cvss": 3.1,
                "exploitability": "Low",
                "mitre": "T1580",
                "description": "Compute inventory discovered during authorized enumeration.",
            },
            "lambda_inventory": {
                "finding": "Lambda functions discovered",
                "severity": "Low",
                "cvss": 3.1,
                "exploitability": "Low",
                "mitre": "T1580",
                "description": "Serverless inventory discovered during authorized enumeration.",
            },
            "iam_inventory": {
                "finding": "IAM principals discovered",
                "severity": "Medium",
                "cvss": 6.5,
                "exploitability": "Medium",
                "mitre": "T1580",
                "description": "Identity inventory discovered during authorized enumeration.",
            },
            "secrets_inventory": {
                "finding": "Secrets Manager entries discovered",
                "severity": "High",
                "cvss": 8.6,
                "exploitability": "High",
                "mitre": "T1552",
                "description": "Secrets inventory discovered during authorized enumeration.",
            },
            "public_s3_bucket": {
                "finding": "Public S3 bucket",
                "severity": "Critical",
                "cvss": 9.8,
                "exploitability": "High",
                "mitre": "T1530",
                "description": "A bucket is publicly readable or publicly exposed through policy or ACL.",
            },
            "overprivileged_iam_role": {
                "finding": "Overprivileged IAM role",
                "severity": "High",
                "cvss": 8.1,
                "exploitability": "Medium",
                "mitre": "T1098",
                "description": "An IAM role grants overly broad permissions such as AdministratorAccess or wildcard actions.",
            },
            "open_security_group": {
                "finding": "Open security group",
                "severity": "High",
                "cvss": 8.0,
                "exploitability": "High",
                "mitre": "T1190",
                "description": "A security group allows unrestricted inbound access from the internet.",
            },
            "exposed_secret": {
                "finding": "Exposed secret",
                "severity": "Critical",
                "cvss": 9.0,
                "exploitability": "High",
                "mitre": "T1552",
                "description": "A secret is discoverable with weak protections, missing rotation, or weak keying controls.",
            },
            "unencrypted_volume": {
                "finding": "Unencrypted volume",
                "severity": "Medium",
                "cvss": 5.9,
                "exploitability": "Medium",
                "mitre": "T1005",
                "description": "A storage volume is not encrypted at rest.",
            },
        }

    def from_code(self, code: str, evidence: dict[str, Any] | None = None) -> RiskFinding:
        template = self._catalog.get(code)
        if template is None:
            return RiskFinding(
                finding=code.replace("_", " ").title(),
                severity="Info",
                cvss=0.0,
                exploitability="Low",
                mitre="T0000",
                description="Unclassified finding generated by the assessment engine.",
                evidence=evidence,
            )
        return RiskFinding(evidence=evidence, **template)

    def score_findings(self, findings: list[RiskFinding]) -> dict[str, Any]:
        score = 0.0
        weights = {
            "Critical": 1.0,
            "High": 0.8,
            "Medium": 0.5,
            "Low": 0.2,
            "Info": 0.0,
        }
        for finding in findings:
            score += finding.cvss * weights.get(finding.severity, 0.1)
        score = min(100.0, round(score, 1))
        return {
            "score": score,
            "risk_level": self._risk_level(score),
            "findings": [finding.to_dict() for finding in findings],
        }

    def _risk_level(self, score: float) -> str:
        if score >= 75:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 25:
            return "medium"
        return "low"
