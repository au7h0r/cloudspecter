from __future__ import annotations

import unittest

from scanner.metadata.assessment import MetadataAssessmentService
from scanner.metadata.providers import get_metadata_provider
from reporting.render import render_markdown


class FakeResponse:
    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    @property
    def ok(self) -> bool:
        return self.status_code < 400


class FakeMetadataSession:
    def get(self, url: str, headers: dict[str, str] | None = None, timeout: int | float | None = None):
        headers = headers or {}
        path = url.split("http://vulnerable.local")[-1]
        if path == url:
            path = url.split("http://protected.local")[-1]

        is_protected = url.startswith("http://protected.local")
        has_token = bool(headers.get("X-aws-ec2-metadata-token"))

        if path == "/latest/meta-data/":
            if is_protected and not has_token:
                return FakeResponse(401, "blocked")
            return FakeResponse(200, "iam/\n")
        if path == "/latest/meta-data/iam/":
            if is_protected and not has_token:
                return FakeResponse(401, "blocked")
            return FakeResponse(200, "security-credentials/\n")
        if path == "/latest/meta-data/iam/security-credentials/":
            if is_protected and not has_token:
                return FakeResponse(401, "blocked")
            return FakeResponse(200, "CloudSpecterLabRole\n")
        return FakeResponse(404, "not found")

    def put(self, url: str, headers: dict[str, str] | None = None, timeout: int | float | None = None):
        if url.endswith("/latest/api/token"):
            return FakeResponse(200, "fake-token")
        return FakeResponse(404, "not found")


class MetadataAssessmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = MetadataAssessmentService()
        self.session = FakeMetadataSession()

    def test_vulnerable_and_protected_reports_have_expected_risk_difference(self) -> None:
        vulnerable = self.service.assess(
            endpoint="http://vulnerable.local",
            provider_name="aws",
            label="vulnerable_mode",
            session=self.session,
        )
        protected = self.service.assess(
            endpoint="http://protected.local",
            provider_name="aws",
            label="protected_mode",
            session=self.session,
        )

        self.assertGreater(vulnerable.risk_score, protected.risk_score)
        self.assertTrue(vulnerable.probe.reachable)
        self.assertTrue(protected.probe.token_required)
        self.assertGreaterEqual(protected.probe.blocked_attempts, 1)
        self.assertGreaterEqual(len(vulnerable.paths), 3)
        self.assertEqual(vulnerable.paths[0].path, "/latest/meta-data/")
        self.assertGreaterEqual(len(vulnerable.findings), 2)
        self.assertEqual(vulnerable.findings[0].mitre, "T1552.005")
        self.assertIn("cloudspecter_metadata_risk_score", {metric["name"] for metric in vulnerable.grafana["metrics"]})

    def test_comparison_report_contains_delta(self) -> None:
        comparison = self.service.compare(
            vulnerable_endpoint="http://vulnerable.local",
            protected_endpoint="http://protected.local",
            provider_name="aws",
            session=self.session,
        )

        data = comparison.to_dict()
        self.assertIn("comparison", data)
        self.assertTrue(data["comparison"]["delta"]["enforcement_improvement"])
        self.assertGreater(data["comparison"]["delta"]["risk_score_difference"], 0)

    def test_provider_extensibility_placeholder(self) -> None:
        provider = get_metadata_provider("azure")
        report = self.service.assess(endpoint="http://example", provider_name=provider.name, session=self.session)
        self.assertEqual(report.provider, "azure")

    def test_markdown_rendering_supports_new_report_shape(self) -> None:
        report = self.service.assess(
            endpoint="http://vulnerable.local",
            provider_name="aws",
            label="vulnerable_mode",
            session=self.session,
        ).to_dict()
        markdown = render_markdown(report)
        self.assertIn("CloudSpecter Metadata Assessment", markdown)
        self.assertIn("Risk score", markdown)


if __name__ == "__main__":
    unittest.main()
