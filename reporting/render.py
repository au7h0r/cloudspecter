from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any


def render_markdown(report: dict[str, Any]) -> str:
    if "comparison" in report and "vulnerable" in report["comparison"]:
        return _render_comparison_markdown(report)
    if "comparison" in report and "vulnerable_environment" in report["comparison"]:
        return _render_legacy_markdown(report)
    if "scope" in report and "findings" in report:
        return _render_aws_audit_markdown(report)
    if "inventory" in report and "counts" in report:
        return _render_aws_inventory_markdown(report)
    return _render_assessment_markdown(report)


def _render_assessment_markdown(report: dict[str, Any]) -> str:
    probe = report["probe"]
    paths = report.get("paths", [])
    findings = report.get("findings", [])
    lines = [
        "# CloudSpecter Metadata Assessment",
        "",
        f"Generated at: {report['generated_at']}",
        f"Provider: {report['provider']}",
        f"Mode: {report['mode']}",
        f"Risk score: {report['risk_score']} ({report['risk_level']})",
        "",
        "## Probe",
        f"- Endpoint: {probe['endpoint']}",
        f"- Reachable: {probe['reachable']}",
        f"- IMDSv2 required: {probe['token_required']}",
        f"- Token endpoint available: {probe['token_endpoint_available']}",
        f"- Blocked attempts: {probe['blocked_attempts']}",
        "",
        "## Non-Sensitive Metadata Enumeration",
    ]
    for item in paths:
        lines.append(f"- {item['path']} -> {item['status_code']} ({'blocked' if item['blocked'] else 'allowed'})")
    lines.extend([
        "",
        "## Findings",
    ])
    for item in findings:
        lines.append(
            f"- {item['finding']} | severity: {item['severity']} | cvss: {item['cvss']} | exploitability: {item['exploitability']} | mitre: {item['mitre']}"
        )
    lines.extend([
        "",
        "## Remediation",
    ])
    for item in report.get("remediation", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def _render_comparison_markdown(report: dict[str, Any]) -> str:
    comparison = report["comparison"]
    vulnerable = comparison["vulnerable"]
    protected = comparison["protected"]
    delta = comparison["delta"]
    lines = [
        "# CloudSpecter Defensive Assessment Comparison",
        "",
        f"Generated at: {report['generated_at']}",
        "",
        "## Vulnerable Mode",
        f"- Risk score: {vulnerable['risk_score']} ({vulnerable['risk_level']})",
        f"- Blocked attempts: {vulnerable['probe']['blocked_attempts']}",
        f"- Findings: {len(vulnerable.get('findings', []))}",
        "",
        "## Protected Mode",
        f"- Risk score: {protected['risk_score']} ({protected['risk_level']})",
        f"- Blocked attempts: {protected['probe']['blocked_attempts']}",
        f"- Findings: {len(protected.get('findings', []))}",
        "",
        "## Delta",
        f"- Risk score difference: {delta['risk_score_difference']}",
        f"- Blocked attempts difference: {delta['blocked_attempts_difference']}",
        f"- Enforcement improvement: {delta['enforcement_improvement']}",
        "",
    ]
    return "\n".join(lines)


def _render_legacy_markdown(report: dict[str, Any]) -> str:
    vulnerable = report["comparison"]["vulnerable_environment"]
    protected = report["comparison"]["protected_environment"]
    posture = report["posture"]

    lines = [
        "# CloudSpecter Defensive Assessment Report",
        "",
        f"Generated at: {report['generated_at']}",
        f"Source: {report['summary']['source']}",
        "",
        "## SSRF Validation",
        f"- Vulnerable checks: {len(vulnerable['ssrf_validation'])}",
        f"- Protected checks: {len(protected['ssrf_validation'])}",
        "",
        "## IMDS Comparison",
        f"- Vulnerable token required: {vulnerable['imds']['token_required']}",
        f"- Protected token required: {protected['imds']['token_required']}",
        "",
        "## Posture Snapshot",
        f"- Account: {posture.get('account_id')}",
        f"- Region: {posture['region']}",
        f"- S3 buckets: {', '.join(posture['s3_buckets']) or 'none'}",
        f"- IAM users: {', '.join(posture['iam_users']) or 'none'}",
        f"- DynamoDB tables: {', '.join(posture['dynamodb_tables']) or 'none'}",
        f"- Secrets: {', '.join(posture['secrets']) or 'none'}",
        "",
        "## Remediation",
    ]

    for item in report["remediation"]:
        lines.append(f"- {item}")

    lines.append("")
    return "\n".join(lines)


def _render_aws_inventory_markdown(report: dict[str, Any]) -> str:
    inventory = report["inventory"]
    counts = report["counts"]
    findings = report.get("findings", [])
    lines = [
        "# CloudSpecter AWS Enumeration Report",
        "",
        f"Generated at: {report['generated_at']}",
        f"Account: {inventory.get('account_id')}",
        f"Region: {inventory['region']}",
        f"Risk score: {report['risk_score']} ({report['risk_level']})",
        "",
        "## Counts",
    ]
    for key, value in counts.items():
        lines.append(f"- {key}: {value}")
    lines.extend([
        "",
        "## Inventory",
        f"- S3 buckets: {', '.join(item['name'] for item in inventory['s3_buckets']) or 'none'}",
        f"- EC2 instances: {', '.join(item['instance_id'] for item in inventory['ec2_instances']) or 'none'}",
        f"- Lambda functions: {', '.join(item['name'] for item in inventory['lambda_functions']) or 'none'}",
        f"- IAM users: {', '.join(item['user_name'] for item in inventory['iam_users']) or 'none'}",
        f"- IAM roles: {', '.join(item['role_name'] for item in inventory['iam_roles']) or 'none'}",
        f"- Secrets: {', '.join(item['name'] for item in inventory['secrets']) or 'none'}",
        "",
        "## Findings",
    ])
    for item in findings:
        lines.append(
            f"- {item['finding']} | severity: {item['severity']} | cvss: {item['cvss']} | exploitability: {item['exploitability']} | mitre: {item['mitre']}"
        )
    lines.extend([
        "",
        "## Remediation",
    ])
    for item in report.get("remediation", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def _render_aws_audit_markdown(report: dict[str, Any]) -> str:
    scope = report["scope"]
    findings = report.get("findings", [])
    lines = [
        "# CloudSpecter AWS Audit Report",
        "",
        f"Generated at: {report['generated_at']}",
        f"Account: {scope.get('account_id')}",
        f"Region: {scope['region']}",
        f"Risk score: {report['risk_score']} ({report['risk_level']})",
        "",
        "## Findings",
    ]
    for item in findings:
        finding = item["finding"]
        lines.append(
            f"- {finding['finding']} | severity: {finding['severity']} | cvss: {finding['cvss']} | exploitability: {finding['exploitability']} | mitre: {finding['mitre']} | resource: {item['resource_type']}:{item['resource_id']}"
        )
    lines.extend([
        "",
        "## Remediation",
    ])
    for item in report.get("remediation", []):
        lines.append(f"- {item}")
    lines.append("")
    return "\n".join(lines)


def save_markdown(report: dict[str, Any], output_path: str | Path) -> Path:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(render_markdown(report), encoding="utf-8")
    return output_file


def save_report(report: dict[str, Any], output_path: str | Path) -> Path:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return output_file


def load_report(report_path: str | Path) -> dict[str, Any]:
    return json.loads(Path(report_path).read_text(encoding="utf-8"))
