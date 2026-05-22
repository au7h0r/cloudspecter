from __future__ import annotations

import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any

import requests

from .models import (
    AssessmentComparison,
    MetadataAssessmentReport,
    MetadataPathFinding,
    MetadataProbeResult,
)
from .providers import AwsMetadataProvider, MetadataProvider, get_metadata_provider
from scanner.risk import RiskFinding, RiskScoringEngine


logger = logging.getLogger(__name__)
risk_engine = RiskScoringEngine()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clamp_score(score: int) -> int:
    return max(0, min(100, score))


def _risk_level(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


class MetadataHttpClient:
    def __init__(self, base_url: str, session: requests.Session | None = None, timeout_seconds: int = 5) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout_seconds = timeout_seconds

    def build_url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not path.startswith("/"):
            path = f"/{path}"
        return f"{self.base_url}{path}"

    def get(self, path: str, headers: dict[str, str] | None = None) -> requests.Response:
        return self.session.get(self.build_url(path), headers=headers or {}, timeout=self.timeout_seconds)

    def put(self, path: str, headers: dict[str, str] | None = None) -> requests.Response:
        return self.session.put(self.build_url(path), headers=headers or {}, timeout=self.timeout_seconds)


class MetadataAssessmentService:
    def __init__(self, logger_: logging.Logger | None = None) -> None:
        self.logger = logger_ or logger

    def assess(
        self,
        endpoint: str,
        provider_name: str = "aws",
        label: str = "lab",
        timeout_seconds: int = 5,
        token_ttl_seconds: int = 60,
        session: requests.Session | None = None,
    ) -> MetadataAssessmentReport:
        provider = get_metadata_provider(provider_name)
        if isinstance(provider, AwsMetadataProvider):
            return self._assess_provider(provider, endpoint, label, timeout_seconds, token_ttl_seconds, session)
        return self._assess_placeholder(provider, endpoint, label, timeout_seconds)

    def compare(
        self,
        vulnerable_endpoint: str,
        protected_endpoint: str,
        provider_name: str = "aws",
        vulnerable_label: str = "vulnerable_mode",
        protected_label: str = "protected_mode",
        timeout_seconds: int = 5,
        token_ttl_seconds: int = 60,
        session: requests.Session | None = None,
    ) -> AssessmentComparison:
        vulnerable = self.assess(
            vulnerable_endpoint,
            provider_name=provider_name,
            label=vulnerable_label,
            timeout_seconds=timeout_seconds,
            token_ttl_seconds=token_ttl_seconds,
            session=session,
        )
        protected = self.assess(
            protected_endpoint,
            provider_name=provider_name,
            label=protected_label,
            timeout_seconds=timeout_seconds,
            token_ttl_seconds=token_ttl_seconds,
            session=session,
        )
        delta = {
            "risk_score_difference": vulnerable.risk_score - protected.risk_score,
            "blocked_attempts_difference": protected.probe.blocked_attempts - vulnerable.probe.blocked_attempts,
            "enforcement_improvement": protected.probe.token_required and not vulnerable.probe.token_required,
        }
        return AssessmentComparison(generated_at=_now_iso(), vulnerable=vulnerable, protected=protected, delta=delta)

    def _assess_provider(
        self,
        provider: MetadataProvider,
        endpoint: str,
        label: str,
        timeout_seconds: int,
        token_ttl_seconds: int,
        session: requests.Session | None,
    ) -> MetadataAssessmentReport:
        client = MetadataHttpClient(endpoint, session=session, timeout_seconds=timeout_seconds)
        blocked_events: list[dict[str, Any]] = []

        reachable = False
        status_code: int | None = None
        token_required = False
        token_endpoint_available = False
        token_value: str | None = None

        try:
            root_response = client.get(provider.root_path)
            reachable = root_response.status_code < 500
            status_code = root_response.status_code
            token_required = root_response.status_code in {401, 403}
            if token_required:
                blocked_events.append(
                    {
                        "event": "blocked_metadata_access",
                        "path": provider.root_path,
                        "status_code": root_response.status_code,
                        "mode": label,
                    }
                )
        except requests.RequestException as exc:
            self.logger.warning("Metadata reachability probe failed for %s: %s", endpoint, exc)
            return self._unreachable_report(provider, endpoint, label, str(exc))

        token_response = None
        try:
            token_response = client.put(
                provider.token_path,
                headers={provider.token_ttl_header: str(token_ttl_seconds)},
            )
            token_endpoint_available = token_response.ok and bool(token_response.text.strip())
            if token_endpoint_available:
                token_value = token_response.text.strip()
        except requests.RequestException as exc:
            self.logger.info("Token endpoint unavailable at %s: %s", endpoint, exc)

        path_findings: list[MetadataPathFinding] = []
        for path in provider.safe_paths:
            path_findings.append(
                self._probe_path(
                    client=client,
                    provider=provider,
                    path=path,
                    token_value=token_value,
                    label=label,
                    blocked_events=blocked_events,
                )
            )

        risk_score = self._risk_score(
            reachable=reachable,
            token_required=token_required,
            token_endpoint_available=token_endpoint_available,
            path_findings=path_findings,
            blocked_events=blocked_events,
        )
        findings = self._build_findings(
            reachable=reachable,
            token_required=token_required,
            token_endpoint_available=token_endpoint_available,
            blocked_events=blocked_events,
            path_findings=path_findings,
        )
        score_payload = risk_engine.score_findings(findings)
        risk_score = int(score_payload["score"])
        remediation = self._remediation(
            token_required=token_required,
            token_endpoint_available=token_endpoint_available,
            reachable=reachable,
        )

        probe = MetadataProbeResult(
            endpoint=endpoint,
            reachable=reachable,
            status_code=status_code,
            token_endpoint_available=token_endpoint_available,
            token_required=token_required,
            blocked_attempts=len(blocked_events),
            blocked_events=blocked_events,
        )

        report = MetadataAssessmentReport(
            generated_at=_now_iso(),
            provider=provider.name,
            label=label,
            endpoint=endpoint,
            mode="protected" if token_required else "vulnerable",
            probe=probe,
            paths=path_findings,
            risk_score=risk_score,
            risk_level=str(score_payload["risk_level"]),
            remediation=remediation,
            findings=findings,
            blocked_events=blocked_events,
            grafana=self._grafana_payload(provider.name, label, endpoint, probe, path_findings, risk_score),
            notes=[
                "Non-sensitive metadata enumeration only; no credential retrieval performed.",
                "Supported providers can be extended for Azure or GCP by implementing the provider protocol.",
            ],
        )
        return report

    def _assess_placeholder(
        self,
        provider: MetadataProvider,
        endpoint: str,
        label: str,
        timeout_seconds: int,
    ) -> MetadataAssessmentReport:
        client = MetadataHttpClient(endpoint, timeout_seconds=timeout_seconds)
        blocked_events = [
            {
                "event": "provider_placeholder",
                "provider": provider.name,
                "message": "Metadata provider not implemented; placeholder returned for extensibility demo.",
            }
        ]
        probe = MetadataProbeResult(
            endpoint=endpoint,
            reachable=False,
            status_code=None,
            token_endpoint_available=False,
            token_required=False,
            blocked_attempts=0,
            blocked_events=blocked_events,
        )
        report = MetadataAssessmentReport(
            generated_at=_now_iso(),
            provider=provider.name,
            label=label,
            endpoint=endpoint,
            mode="unknown",
            probe=probe,
            paths=[],
            risk_score=0,
            risk_level="low",
            remediation=[f"Implement a {provider.name.upper()} metadata provider before assessing this platform."],
            findings=[],
            blocked_events=blocked_events,
            grafana=self._grafana_payload(provider.name, label, endpoint, probe, [], 0),
            notes=["Placeholder metadata provider exists to keep the architecture extensible."],
        )
        return report

    def _unreachable_report(self, provider: MetadataProvider, endpoint: str, label: str, error: str) -> MetadataAssessmentReport:
        probe = MetadataProbeResult(
            endpoint=endpoint,
            reachable=False,
            status_code=None,
            token_endpoint_available=False,
            token_required=False,
            blocked_attempts=0,
            blocked_events=[{"event": "unreachable", "error": error}],
        )
        report = MetadataAssessmentReport(
            generated_at=_now_iso(),
            provider=provider.name,
            label=label,
            endpoint=endpoint,
            mode="unreachable",
            probe=probe,
            paths=[],
            risk_score=0,
            risk_level="low",
            remediation=["Verify the metadata endpoint is reachable inside the authorized lab environment."],
            findings=[],
            blocked_events=probe.blocked_events,
            grafana=self._grafana_payload(provider.name, label, endpoint, probe, [], 0),
            notes=[error],
        )
        return report

    def _probe_path(
        self,
        client: MetadataHttpClient,
        provider: MetadataProvider,
        path: str,
        token_value: str | None,
        label: str,
        blocked_events: list[dict[str, Any]],
    ) -> MetadataPathFinding:
        try:
            response = client.get(path)
            blocked = response.status_code in {401, 403}
            if blocked:
                blocked_events.append(
                    {
                        "event": "blocked_metadata_access",
                        "path": path,
                        "status_code": response.status_code,
                        "mode": label,
                    }
                )
            if blocked and token_value:
                response = client.get(path, headers=provider.auth_headers(token_value))
                blocked = response.status_code in {401, 403}
            preview = response.text[:200].replace("\r", " ").replace("\n", " ")
            return MetadataPathFinding(
                path=path,
                status_code=response.status_code,
                reachable=response.ok,
                blocked=blocked,
                sensitive=False,
                preview=preview,
            )
        except requests.RequestException as exc:
            blocked_events.append(
                {
                    "event": "request_exception",
                    "path": path,
                    "mode": label,
                    "error": str(exc),
                }
            )
            return MetadataPathFinding(
                path=path,
                status_code=None,
                reachable=False,
                blocked=True,
                sensitive=False,
                preview=str(exc),
            )

    def _risk_score(
        self,
        reachable: bool,
        token_required: bool,
        token_endpoint_available: bool,
        path_findings: list[MetadataPathFinding],
        blocked_events: list[dict[str, Any]],
    ) -> int:
        score = 0
        if reachable:
            score += 30
        if any(path.path.endswith("iam/security-credentials/") and path.reachable for path in path_findings):
            score += 25
        if not token_required:
            score += 30
        if not token_endpoint_available:
            score += 15
        if blocked_events:
            score -= 10
        if token_required:
            score -= 15
        return _clamp_score(score)

    def _build_findings(
        self,
        reachable: bool,
        token_required: bool,
        token_endpoint_available: bool,
        blocked_events: list[dict[str, Any]],
        path_findings: list[MetadataPathFinding],
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []
        if reachable:
            findings.append(risk_engine.from_code("metadata_reachable", {"endpoint": path_findings[0].path if path_findings else None}))
        if token_required:
            findings.append(risk_engine.from_code("imdsv2_required", {"token_endpoint_available": token_endpoint_available}))
        else:
            findings.append(risk_engine.from_code("imdsv1_enabled", {"token_endpoint_available": token_endpoint_available}))
        if blocked_events:
            findings.append(risk_engine.from_code("blocked_metadata_access", {"blocked_attempts": len(blocked_events)}))
        return findings

    def _remediation(
        self,
        token_required: bool,
        token_endpoint_available: bool,
        reachable: bool,
    ) -> list[str]:
        recommendations = [
            "Require IMDSv2 tokens for all metadata access.",
            "Keep metadata endpoints private to the instance boundary.",
            "Log and alert on any blocked metadata access attempts.",
        ]
        if reachable and not token_required:
            recommendations.append("Enable IMDSv2 enforcement in the instance metadata options.")
        if not token_endpoint_available:
            recommendations.append("Confirm the platform supports token issuance and short TTL validation.")
        return recommendations

    def _grafana_payload(
        self,
        provider: str,
        label: str,
        endpoint: str,
        probe: MetadataProbeResult,
        path_findings: list[MetadataPathFinding],
        risk_score: int,
    ) -> dict[str, Any]:
        return {
            "metrics": [
                {"name": "cloudspecter_metadata_reachability", "value": int(probe.reachable), "labels": {"provider": provider, "label": label, "endpoint": endpoint}},
                {"name": "cloudspecter_metadata_token_required", "value": int(probe.token_required), "labels": {"provider": provider, "label": label, "endpoint": endpoint}},
                {"name": "cloudspecter_metadata_token_endpoint_available", "value": int(probe.token_endpoint_available), "labels": {"provider": provider, "label": label, "endpoint": endpoint}},
                {"name": "cloudspecter_metadata_blocked_attempts_total", "value": probe.blocked_attempts, "labels": {"provider": provider, "label": label, "endpoint": endpoint}},
                {"name": "cloudspecter_metadata_risk_score", "value": risk_score, "labels": {"provider": provider, "label": label, "endpoint": endpoint}},
                {"name": "cloudspecter_metadata_paths_enumerated", "value": len(path_findings), "labels": {"provider": provider, "label": label, "endpoint": endpoint}},
            ],
            "blocked_events": list(probe.blocked_events),
            "series": [
                {
                    "metric": "metadata_path_status_code",
                    "points": [
                        {"path": finding.path, "value": finding.status_code or 0, "blocked": finding.blocked}
                        for finding in path_findings
                    ],
                }
            ],
        }
