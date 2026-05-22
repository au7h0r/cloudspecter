from __future__ import annotations

import unittest

from scanner.risk import RiskScoringEngine


class RiskEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = RiskScoringEngine()

    def test_standard_finding_shape(self) -> None:
        finding = self.engine.from_code("imdsv1_enabled", {"endpoint": "http://localhost:1338"})
        data = finding.to_dict()

        self.assertEqual(data["finding"], "IMDSv1 enabled")
        self.assertEqual(data["severity"], "Critical")
        self.assertAlmostEqual(data["cvss"], 9.1)
        self.assertEqual(data["exploitability"], "High")
        self.assertEqual(data["mitre"], "T1552.005")

    def test_scoring_aggregates_findings(self) -> None:
        findings = [
            self.engine.from_code("imdsv1_enabled"),
            self.engine.from_code("blocked_metadata_access"),
        ]
        result = self.engine.score_findings(findings)

        self.assertIn("score", result)
        self.assertIn("risk_level", result)
        self.assertEqual(len(result["findings"]), 2)
        self.assertGreater(result["score"], 0)


if __name__ == "__main__":
    unittest.main()
