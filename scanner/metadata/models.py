from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any

from scanner.risk import RiskFinding


@dataclass
class MetadataProbeResult:
    endpoint: str
    reachable: bool
    status_code: int | None
    token_endpoint_available: bool
    token_required: bool
    blocked_attempts: int
    blocked_events: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class MetadataPathFinding:
    path: str
    status_code: int | None
    reachable: bool
    blocked: bool
    sensitive: bool
    preview: str


@dataclass
class MetadataAssessmentReport:
    generated_at: str
    provider: str
    label: str
    endpoint: str
    mode: str
    probe: MetadataProbeResult
    paths: list[MetadataPathFinding]
    risk_score: int
    risk_level: str
    remediation: list[str]
    findings: list[RiskFinding]
    blocked_events: list[dict[str, Any]]
    grafana: dict[str, Any]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "provider": self.provider,
            "label": self.label,
            "endpoint": self.endpoint,
            "mode": self.mode,
            "probe": asdict(self.probe),
            "paths": [asdict(item) for item in self.paths],
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "remediation": list(self.remediation),
            "findings": [finding.to_dict() for finding in self.findings],
            "blocked_events": list(self.blocked_events),
            "grafana": self.grafana,
            "notes": list(self.notes),
        }


@dataclass
class AssessmentComparison:
    generated_at: str
    vulnerable: MetadataAssessmentReport
    protected: MetadataAssessmentReport
    delta: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "comparison": {
                "vulnerable": self.vulnerable.to_dict(),
                "protected": self.protected.to_dict(),
                "delta": self.delta,
            },
        }
