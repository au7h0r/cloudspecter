from __future__ import annotations

import json
from pathlib import Path
import unittest


class GrafanaDashboardTests(unittest.TestCase):
    def test_dashboard_includes_requested_panels(self) -> None:
        dashboard_path = Path(__file__).resolve().parents[1] / "docker" / "grafana" / "dashboards" / "cloudspecter-dashboard.json"
        data = json.loads(dashboard_path.read_text(encoding="utf-8"))
        titles = {panel["title"] for panel in data["panels"]}

        self.assertIn("Live Attacks", titles)
        self.assertIn("Credential Theft Attempts", titles)
        self.assertIn("Cloud Misconfigurations", titles)

    def test_prometheus_targets_include_scanner(self) -> None:
        prometheus_path = Path(__file__).resolve().parents[1] / "docker" / "prometheus" / "prometheus.yml"
        text = prometheus_path.read_text(encoding="utf-8")

        self.assertIn("scanner:8080", text)


if __name__ == "__main__":
    unittest.main()
