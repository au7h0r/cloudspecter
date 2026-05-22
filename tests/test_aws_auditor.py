from __future__ import annotations

import unittest

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
            ("ec2", "describe_instances"): FakePaginator([
                {"Reservations": [{"Instances": [{"InstanceId": "i-1", "MetadataOptions": {"HttpTokens": "optional"}}]}]},
            ]),
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


if __name__ == "__main__":
    unittest.main()
