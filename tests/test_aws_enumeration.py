from __future__ import annotations

import unittest

from reporting.render import render_markdown
from scanner.aws.engine import AwsEnumerationEngine


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
            ("ec2", "describe_instances"): FakePaginator([
                {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": "i-123",
                                    "State": {"Name": "running"},
                                    "InstanceType": "t3.micro",
                                    "PublicIpAddress": "1.2.3.4",
                                    "PrivateIpAddress": "10.0.0.10",
                                    "Tags": [{"Key": "Name", "Value": "app"}],
                                }
                            ]
                        }
                    ]
                }
            ]),
            ("lambda", "list_functions"): FakePaginator([
                {
                    "Functions": [
                        {
                            "FunctionName": "cloudspecter-fn",
                            "Runtime": "python3.11",
                            "Handler": "app.handler",
                            "LastModified": "2026-05-23T12:00:00Z",
                            "CodeSize": 1024,
                            "Version": "$LATEST",
                        }
                    ]
                }
            ]),
            ("iam", "list_users"): FakePaginator([
                {
                    "Users": [
                        {
                            "UserName": "alice",
                            "UserId": "AID123",
                            "Arn": "arn:aws:iam::123456789012:user/alice",
                            "CreateDate": "2026-05-23T12:00:00Z",
                        }
                    ]
                }
            ]),
            ("iam", "list_roles"): FakePaginator([
                {
                    "Roles": [
                        {
                            "RoleName": "CloudSpecterRole",
                            "RoleId": "AR123",
                            "Arn": "arn:aws:iam::123456789012:role/CloudSpecterRole",
                            "CreateDate": "2026-05-23T12:00:00Z",
                        }
                    ]
                }
            ]),
            ("secretsmanager", "list_secrets"): FakePaginator([
                {
                    "SecretList": [
                        {
                            "Name": "internal-secrets",
                            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:internal-secrets",
                            "Description": "demo",
                            "LastChangedDate": "2026-05-23T12:00:00Z",
                            "RotationEnabled": True,
                        }
                    ]
                }
            ]),
        }
        return data[(self.service_name, operation_name)]

    def list_buckets(self):
        return {"Buckets": [{"Name": "finance-data", "CreationDate": "2026-05-23T12:00:00Z"}]}

    def get_bucket_location(self, Bucket: str):
        return {"LocationConstraint": "us-east-1"}

    def list_users(self):
        return {"Users": []}

    def list_roles(self):
        return {"Roles": []}

    def list_functions(self):
        return {"Functions": []}

    def list_secrets(self):
        return {"SecretList": []}

    def get_caller_identity(self):
        return {"Account": "123456789012"}


class FakeSession:
    def client(self, service_name: str, region_name=None, endpoint_url=None):
        return FakeClient(service_name)


class AwsEnumerationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = AwsEnumerationEngine(session=FakeSession())

    def test_enumeration_collects_supported_resource_types(self) -> None:
        report = self.engine.enumerate(region_name="us-east-1")
        data = report.to_dict()

        self.assertEqual(data["inventory"]["account_id"], "123456789012")
        self.assertEqual(data["counts"]["s3_buckets"], 1)
        self.assertEqual(data["counts"]["ec2_instances"], 1)
        self.assertEqual(data["counts"]["lambda_functions"], 1)
        self.assertEqual(data["counts"]["iam_users"], 1)
        self.assertEqual(data["counts"]["iam_roles"], 1)
        self.assertEqual(data["counts"]["secrets"], 1)
        self.assertIn("cloudspecter_aws_risk_score", {metric["name"] for metric in data["grafana"]["metrics"]})

    def test_markdown_rendering_supports_aws_inventory(self) -> None:
        report = self.engine.enumerate(region_name="us-east-1").to_dict()
        markdown = render_markdown(report)
        self.assertIn("CloudSpecter AWS Enumeration Report", markdown)
        self.assertIn("finance-data", markdown)


if __name__ == "__main__":
    unittest.main()
