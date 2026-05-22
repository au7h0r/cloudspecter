from __future__ import annotations

import unittest
from unittest.mock import patch

from scanner.api import app


class FakeReport:
    def __init__(self, payload):
        self.payload = payload

    def to_dict(self):
        return self.payload


class ScannerApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = app.test_client()

    @patch("scanner.api.service.assess")
    def test_assess_endpoint_returns_json(self, mock_assess):
        mock_assess.return_value = FakeReport({"risk_score": 10, "provider": "aws"})
        response = self.client.post("/api/v1/metadata/assess", json={"endpoint": "http://localhost:1338"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk_score"], 10)

    @patch("scanner.api.service.compare")
    def test_compare_endpoint_returns_json(self, mock_compare):
        mock_compare.return_value = FakeReport({"comparison": {"delta": {"risk_score_difference": 50}}})
        response = self.client.post(
            "/api/v1/metadata/compare",
            json={"vulnerable_endpoint": "http://a", "protected_endpoint": "http://b"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["comparison"]["delta"]["risk_score_difference"], 50)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["service"], "cloudspecter-scanner-api")

    @patch("scanner.api.aws_engine.enumerate")
    def test_aws_enumeration_endpoint_returns_json(self, mock_enumerate):
        mock_enumerate.return_value = FakeReport({"counts": {"s3_buckets": 1}, "risk_score": 12})
        response = self.client.post("/api/v1/aws/enumerate", json={"region": "us-east-1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["counts"]["s3_buckets"], 1)

    @patch("scanner.api.aws_auditor.audit")
    def test_aws_audit_endpoint_returns_json(self, mock_audit):
        mock_audit.return_value = FakeReport({"risk_score": 91, "findings": [{"finding": {"finding": "Public S3 bucket"}}]})
        response = self.client.post("/api/v1/aws/audit", json={"region": "us-east-1"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["risk_score"], 91)


if __name__ == "__main__":
    unittest.main()
