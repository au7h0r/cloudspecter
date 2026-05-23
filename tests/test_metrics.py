from __future__ import annotations

import unittest
from unittest.mock import patch

from backend.app import app as backend_app
from backend.imds_emulator import app as imds_app


class MetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend_client = backend_app.test_client()
        self.imds_client = imds_app.test_client()

    @patch("backend.app.requests.get")
    def test_backend_reports_ssrf_attempts(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "ok"

        response = self.backend_client.get("/api/fetch?url=http://example.com")
        self.assertEqual(response.status_code, 200)

        metrics_response = self.backend_client.get("/metrics")
        metrics_text = metrics_response.data.decode("utf-8")
        self.assertIn("cloudspecter_ssrf_attempts_total", metrics_text)
        self.assertIn('result="success"', metrics_text)

    def test_imds_reports_metadata_access_and_failed_token_requests(self):
        response = self.imds_client.get("/latest/meta-data/")
        self.assertEqual(response.status_code, 200)

        failed_token_response = self.imds_client.put("/latest/api/token")
        self.assertEqual(failed_token_response.status_code, 400)

        metrics_response = self.imds_client.get("/metrics")
        metrics_text = metrics_response.data.decode("utf-8")
        self.assertIn("cloudspecter_metadata_access_total", metrics_text)
        self.assertIn("cloudspecter_failed_token_requests_total", metrics_text)


if __name__ == "__main__":
    unittest.main()
