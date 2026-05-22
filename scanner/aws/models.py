from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from scanner.risk import RiskFinding


@dataclass
class AwsResourceInventory:
    account_id: str | None
    region: str
    source: str
    s3_buckets: list[dict[str, Any]] = field(default_factory=list)
    ec2_instances: list[dict[str, Any]] = field(default_factory=list)
    lambda_functions: list[dict[str, Any]] = field(default_factory=list)
    iam_users: list[dict[str, Any]] = field(default_factory=list)
    iam_roles: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AwsEnumerationReport:
    generated_at: str
    inventory: AwsResourceInventory
    counts: dict[str, int]
    risk_score: int
    risk_level: str
    remediation: list[str]
    findings: list[RiskFinding]
    grafana: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "inventory": self.inventory.to_dict(),
            "counts": dict(self.counts),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "remediation": list(self.remediation),
            "findings": [finding.to_dict() for finding in self.findings],
            "grafana": self.grafana,
            "notes": list(self.notes),
        }
