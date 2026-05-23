from __future__ import annotations

import io
import json
import logging

from flask import Flask, Response, jsonify, request, send_file
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, generate_latest

from scanner.aws_auditor.engine import AwsAuditorEngine
from reporting.render import save_html, save_markdown, save_pdf, save_report, render_pdf
from scanner.aws.engine import AwsEnumerationEngine
from scanner.metadata.assessment import MetadataAssessmentService


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Minimal CORS support so the frontend dev server (on a different port) can call the API
# We avoid adding a new dependency by setting CORS headers on responses and handling
# preflight OPTIONS requests here.
@app.after_request
def _add_cors_headers(response):
    response.headers.setdefault("Access-Control-Allow-Origin", "*")
    response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type,Authorization")
    response.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
    return response


@app.before_request
def _handle_options_preflight():
    # Return early for preflight requests
    if request.method == "OPTIONS":
        resp = app.make_response("")
        resp.headers.setdefault("Access-Control-Allow-Origin", "*")
        resp.headers.setdefault("Access-Control-Allow-Headers", "Content-Type,Authorization")
        resp.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        return resp
service = MetadataAssessmentService(logger_=logger)
aws_engine = AwsEnumerationEngine(logger_=logger)
aws_auditor = AwsAuditorEngine(logger_=logger)

last_reports: dict[str, dict] = {
    "aws-audit": None,
    "assessment": None,
    "comparison": None,
}

AUDIT_FINDINGS = Gauge(
    "cloudspecter_audit_findings_total",
    "Latest total number of AWS audit findings",
    ["region", "source"],
)
AUDIT_PUBLIC_S3 = Gauge(
    "cloudspecter_audit_public_s3_total",
    "Latest count of public S3 findings",
    ["region", "source"],
)
AUDIT_IMDSV1 = Gauge(
    "cloudspecter_audit_imdsv1_total",
    "Latest count of IMDSv1-enabled instances",
    ["region", "source"],
)
AUDIT_OPEN_SG = Gauge(
    "cloudspecter_audit_open_sg_total",
    "Latest count of open security group findings",
    ["region", "source"],
)
AUDIT_OVERPRIVILEGED_ROLES = Gauge(
    "cloudspecter_audit_overprivileged_roles_total",
    "Latest count of overprivileged IAM role findings",
    ["region", "source"],
)
AUDIT_EXPOSED_SECRETS = Gauge(
    "cloudspecter_audit_exposed_secrets_total",
    "Latest count of exposed secret findings",
    ["region", "source"],
)
AUDIT_UNENCRYPTED_VOLUMES = Gauge(
    "cloudspecter_audit_unencrypted_volumes_total",
    "Latest count of unencrypted volume findings",
    ["region", "source"],
)


def _update_audit_metrics(report: dict[str, object]) -> None:
    scope = report.get("scope", {})
    region = str(scope.get("region", "unknown"))
    source = str(scope.get("source", "unknown"))
    counts = report.get("counts", {})

    AUDIT_FINDINGS.labels(region=region, source=source).set(len(report.get("findings", [])))
    AUDIT_PUBLIC_S3.labels(region=region, source=source).set(int(counts.get("public_s3", 0)))
    AUDIT_IMDSV1.labels(region=region, source=source).set(int(counts.get("imdsv1", 0)))
    AUDIT_OPEN_SG.labels(region=region, source=source).set(int(counts.get("open_security_group", 0)))
    AUDIT_OVERPRIVILEGED_ROLES.labels(region=region, source=source).set(int(counts.get("overprivileged_iam_role", 0)))
    AUDIT_EXPOSED_SECRETS.labels(region=region, source=source).set(int(counts.get("exposed_secret", 0)))
    AUDIT_UNENCRYPTED_VOLUMES.labels(region=region, source=source).set(int(counts.get("unencrypted_volume", 0)))


@app.get("/health")
def health():
    return jsonify({"status": "healthy", "service": "cloudspecter-scanner-api"})


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


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

    report_dict = report.to_dict()
    last_reports["assessment"] = report_dict

    return jsonify(report_dict)


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
    report_dict = comparison.to_dict()
    last_reports["comparison"] = report_dict
    return jsonify(report_dict)


@app.post("/api/v1/metadata/report")
def render_report():
    payload = request.get_json(silent=True) or {}
    report = payload.get("report")
    if not report:
        return jsonify({"error": "missing report"}), 400

    json_path = payload.get("json_path", "artifacts/reports/cloudspecter-api-report.json")
    markdown_path = payload.get("markdown_path", "artifacts/reports/cloudspecter-api-report.md")
    html_path = payload.get("html_path", "artifacts/reports/cloudspecter-api-report.html")
    pdf_path = payload.get("pdf_path", "artifacts/reports/cloudspecter-api-report.pdf")
    json_file = save_report(report, json_path)
    md_file = save_markdown(report, markdown_path)
    html_file = save_html(report, html_path)
    pdf_file = save_pdf(report, pdf_path)
    return jsonify({"json": str(json_file), "markdown": str(md_file), "html": str(html_file), "pdf": str(pdf_file)})


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
    report_dict = report.to_dict()
    _update_audit_metrics(report_dict)
    last_reports["aws-audit"] = report_dict
    return jsonify(report_dict)

@app.get("/api/v1/reports/<report_id>/pdf")
def download_report(report_id):
    report_data = last_reports.get(report_id)
    if not report_data:
        return jsonify({"error": "No data available for this report. Please run the analysis first."}), 404

    try:
        pdf_bytes = render_pdf(report_data, engine="reportlab")
        return send_file(
            io.BytesIO(pdf_bytes),
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"cloudspecter-{report_id}.pdf"
        )
    except Exception as e:
        logger.error(f"Failed to generate PDF: {e}")
        return jsonify({"error": "Failed to generate PDF"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)