from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from scanner.risk import RiskFinding


@dataclass
class AwsAuditScope:
    region: str
    source: str
    account_id: str | None


@dataclass
class AwsAuditFinding:
    category: str
    resource_type: str
    resource_id: str
    finding: RiskFinding
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "finding": self.finding.to_dict(),
            "evidence": dict(self.evidence),
        }


@dataclass
class AwsAuditReport:
    generated_at: str
    scope: AwsAuditScope
    findings: list[AwsAuditFinding]
    counts: dict[str, int]
    risk_score: int
    risk_level: str
    remediation: list[str]
    grafana: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "scope": asdict(self.scope),
            "findings": [finding.to_dict() for finding in self.findings],
            "counts": dict(self.counts),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "remediation": list(self.remediation),
            "grafana": self.grafana,
            "notes": list(self.notes),
        }
