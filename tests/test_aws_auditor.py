from __future__ import annotations

import sys
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from reporting.render import render_html, save_html, save_pdf
from scanner.aws_auditor.engine import AwsAuditorEngine


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self):
        for page in self.pages:
            yield page


class FakeClient:
    def __init__(self, service_name: str):
        self.service_name = service_name

    def get_paginator(self, operation_name: str):
        data = {
            ("ec2", "describe_security_groups"): FakePaginator([
                {"SecurityGroups": [{"GroupId": "sg-1", "GroupName": "open", "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}]},
            ]),
            ("ec2", "describe_volumes"): FakePaginator([
                {"Volumes": [{"VolumeId": "vol-1", "Encrypted": False, "State": "in-use", "Size": 8}]},
            ]),
            ("iam", "list_roles"): FakePaginator([
                {"Roles": [{"RoleName": "admin-role"}]},
            ]),
            ("secretsmanager", "list_secrets"): FakePaginator([
                {"SecretList": [{"Name": "internal-secrets", "RotationEnabled": False, "KmsKeyId": None, "ARN": "arn:aws:secretsmanager:us-east-1:123:secret:internal-secrets"}]},
            ]),
        }
        return data[(self.service_name, operation_name)]

    def describe_instances(self, NextToken=None):
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1",
                            "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"},
                        },
                        {
                            "InstanceId": "i-2",
                            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
                        },
                    ]
                }
            ]
        }

    def list_buckets(self):
        return {"Buckets": [{"Name": "public-bucket"}]}

    def get_bucket_policy_status(self, Bucket: str):
        return {"PolicyStatus": {"IsPublic": True}}

    def get_bucket_acl(self, Bucket: str):
        return {"Grants": [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}]}

    def get_public_access_block(self, Bucket: str):
        return {"PublicAccessBlockConfiguration": {}}

    def list_attached_role_policies(self, RoleName: str):
        return {"AttachedPolicies": [{"PolicyName": "AdministratorAccess"}]}

    def list_role_policies(self, RoleName: str):
        return {"PolicyNames": ["inline-admin"]}

    def get_role_policy(self, RoleName: str, PolicyName: str):
        return {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}

    def get_caller_identity(self):
        return {"Account": "123456789012"}


class FakeSession:
    def client(self, service_name: str, region_name=None, endpoint_url=None):
        return FakeClient(service_name)


def _fake_weasyprint_module() -> types.ModuleType:
    module = types.ModuleType("weasyprint")

    class HTML:
        def __init__(self, string: str):
            self.string = string

        def write_pdf(self) -> bytes:
            return b"%PDF-weasyprint\n"

    module.HTML = HTML
    return module


def _fake_reportlab_modules() -> dict[str, types.ModuleType]:
    modules: dict[str, types.ModuleType] = {}

    reportlab = types.ModuleType("reportlab")
    lib = types.ModuleType("reportlab.lib")
    colors = types.ModuleType("reportlab.lib.colors")
    pagesizes = types.ModuleType("reportlab.lib.pagesizes")
    units = types.ModuleType("reportlab.lib.units")
    pdfbase = types.ModuleType("reportlab.pdfbase")
    pdfmetrics = types.ModuleType("reportlab.pdfbase.pdfmetrics")
    pdfgen = types.ModuleType("reportlab.pdfgen")
    canvas_module = types.ModuleType("reportlab.pdfgen.canvas")

    colors.HexColor = lambda value: value
    colors.black = "black"
    pagesizes.A4 = (595.27, 841.89)
    units.mm = 1
    pdfmetrics.stringWidth = lambda text, font_name, font_size: len(text)

    class Canvas:
        def __init__(self, buffer, pagesize=None):
            self.buffer = buffer

        def setTitle(self, title):
            self.title = title

        def setAuthor(self, author):
            self.author = author

        def showPage(self):
            pass

        def setFont(self, font_name, font_size):
            pass

        def drawString(self, x, y, text):
            pass

        def setFillColor(self, color):
            pass

        def save(self):
            self.buffer.write(b"%PDF-reportlab\n")

    canvas_module.Canvas = Canvas
    pdfgen.canvas = canvas_module
    lib.colors = colors
    lib.pagesizes = pagesizes
    lib.units = units
    pdfbase.pdfmetrics = pdfmetrics
    reportlab.lib = lib
    reportlab.pdfbase = pdfbase
    reportlab.pdfgen = pdfgen

    modules["reportlab"] = reportlab
    modules["reportlab.lib"] = lib
    modules["reportlab.lib.colors"] = colors
    modules["reportlab.lib.pagesizes"] = pagesizes
    modules["reportlab.lib.units"] = units
    modules["reportlab.pdfbase"] = pdfbase
    modules["reportlab.pdfbase.pdfmetrics"] = pdfmetrics
    modules["reportlab.pdfgen"] = pdfgen
    modules["reportlab.pdfgen.canvas"] = canvas_module
    return modules


class AwsAuditorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = AwsAuditorEngine(session=FakeSession())

    def test_audit_finds_expected_risks(self) -> None:
        report = self.engine.audit(region_name="us-east-1")
        data = report.to_dict()

        self.assertGreaterEqual(data["risk_score"], 0)
        self.assertGreaterEqual(len(data["findings"]), 5)
        finding_names = {item["finding"]["finding"] for item in data["findings"]}
        self.assertIn("IMDSv1 enabled", finding_names)
        self.assertIn("IMDSv2 enforced", finding_names)
        self.assertIn("Public S3 bucket", finding_names)
        self.assertIn("Overprivileged IAM role", finding_names)
        self.assertIn("Open security group", finding_names)
        self.assertIn("Exposed secret", finding_names)
        self.assertIn("Unencrypted volume", finding_names)

    def test_grafana_payload_includes_metrics(self) -> None:
        report = self.engine.audit(region_name="us-east-1")
        metrics = {metric["name"] for metric in report.grafana["metrics"]}
        self.assertIn("cloudspecter_audit_risk_score", metrics)
        self.assertIn("cloudspecter_audit_open_sg_total", metrics)

    def test_html_rendering_includes_requested_sections(self) -> None:
        report = self.engine.audit(region_name="us-east-1").to_dict()
        html = render_html(report)

        self.assertIn("Executive Summary", html)
        self.assertIn("Visualizations", html)
        self.assertIn("Severity Distribution", html)
        self.assertIn("Attack Timeline", html)
        self.assertIn("Exploited Assets", html)
        self.assertIn("Findings", html)
        self.assertIn("Risk Ratings", html)
        self.assertIn("MITRE Mapping", html)
        self.assertIn("Screenshots", html)
        self.assertIn("Remediation", html)
        self.assertIn("<svg", html)

    def test_save_html_writes_report_file(self) -> None:
        report = self.engine.audit(region_name="us-east-1").to_dict()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "audit.html"
            saved_path = save_html(report, output_path)
            self.assertTrue(saved_path.exists())
            self.assertIn("CloudSpecter AWS Audit Report", saved_path.read_text(encoding="utf-8"))

    def test_save_pdf_uses_weasyprint_when_available(self) -> None:
        report = self.engine.audit(region_name="us-east-1").to_dict()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "audit-weasyprint.pdf"
            with patch.dict(sys.modules, {"weasyprint": _fake_weasyprint_module()}):
                saved_path = save_pdf(report, output_path, engine="weasyprint")
            self.assertTrue(saved_path.exists())
            self.assertEqual(saved_path.read_bytes(), b"%PDF-weasyprint\n")

    def test_save_pdf_uses_reportlab_fallback(self) -> None:
        report = self.engine.audit(region_name="us-east-1").to_dict()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "audit-reportlab.pdf"
            with patch.dict(sys.modules, _fake_reportlab_modules()):
                saved_path = save_pdf(report, output_path, engine="reportlab")
            self.assertTrue(saved_path.exists())
            self.assertEqual(saved_path.read_bytes(), b"%PDF-reportlab\n")


if __name__ == "__main__":
    unittest.main()
