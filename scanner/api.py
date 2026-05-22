from __future__ import annotations

import json
import logging

from flask import Flask, jsonify, request

from scanner.aws_auditor.engine import AwsAuditorEngine
from reporting.render import save_markdown, save_report
from scanner.aws.engine import AwsEnumerationEngine
from scanner.metadata.assessment import MetadataAssessmentService


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
service = MetadataAssessmentService(logger_=logger)
aws_engine = AwsEnumerationEngine(logger_=logger)
aws_auditor = AwsAuditorEngine(logger_=logger)


@app.get("/health")
def health():
    return jsonify({"status": "healthy", "service": "cloudspecter-scanner-api"})


@app.get("/api/v1/providers")
def providers():
    return jsonify({"providers": ["aws", "azure", "gcp"]})


@app.post("/api/v1/metadata/assess")
def assess_metadata():
    payload = request.get_json(silent=True) or {}
    endpoint = payload.get("endpoint") or request.args.get("endpoint")
    provider = payload.get("provider", "aws")
    label = payload.get("label", "lab")
    timeout_seconds = int(payload.get("timeout_seconds", 5))
    token_ttl_seconds = int(payload.get("token_ttl_seconds", 60))

    if not endpoint:
        return jsonify({"error": "missing endpoint"}), 400

    report = service.assess(
        endpoint=endpoint,
        provider_name=provider,
        label=label,
        timeout_seconds=timeout_seconds,
        token_ttl_seconds=token_ttl_seconds,
    )

    return jsonify(report.to_dict())


@app.post("/api/v1/metadata/compare")
def compare_metadata():
    payload = request.get_json(silent=True) or {}
    vulnerable_endpoint = payload.get("vulnerable_endpoint")
    protected_endpoint = payload.get("protected_endpoint")
    provider = payload.get("provider", "aws")
    if not vulnerable_endpoint or not protected_endpoint:
        return jsonify({"error": "missing vulnerable_endpoint or protected_endpoint"}), 400

    comparison = service.compare(
        vulnerable_endpoint=vulnerable_endpoint,
        protected_endpoint=protected_endpoint,
        provider_name=provider,
        vulnerable_label=payload.get("vulnerable_label", "vulnerable_mode"),
        protected_label=payload.get("protected_label", "protected_mode"),
    )
    return jsonify(comparison.to_dict())


@app.post("/api/v1/metadata/report")
def render_report():
    payload = request.get_json(silent=True) or {}
    report = payload.get("report")
    if not report:
        return jsonify({"error": "missing report"}), 400

    json_path = payload.get("json_path", "artifacts/reports/cloudspecter-api-report.json")
    markdown_path = payload.get("markdown_path", "artifacts/reports/cloudspecter-api-report.md")
    json_file = save_report(report, json_path)
    md_file = save_markdown(report, markdown_path)
    return jsonify({"json": str(json_file), "markdown": str(md_file)})


@app.post("/api/v1/aws/enumerate")
def enumerate_aws():
    payload = request.get_json(silent=True) or {}
    region = payload.get("region", "us-east-1")
    endpoint_url = payload.get("endpoint_url")
    report = aws_engine.enumerate(region_name=region, endpoint_url=endpoint_url, source_label=payload.get("source_label", "authorized_aws"))
    return jsonify(report.to_dict())


@app.post("/api/v1/aws/audit")
def audit_aws():
    payload = request.get_json(silent=True) or {}
    region = payload.get("region", "us-east-1")
    endpoint_url = payload.get("endpoint_url")
    report = aws_auditor.audit(region_name=region, endpoint_url=endpoint_url, source_label=payload.get("source_label", "authorized_aws"))
    return jsonify(report.to_dict())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)