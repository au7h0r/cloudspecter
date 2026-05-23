from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reporting.render import save_html, save_markdown, save_pdf, save_report
from scanner.aws_auditor.engine import AwsAuditorEngine
from scanner.metadata.assessment import MetadataAssessmentService


def _build_compare_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--vulnerable-base-url", required=True, help="Base URL of the vulnerable lab service")
    parser.add_argument("--protected-base-url", required=True, help="Base URL of the protected lab service")
    parser.add_argument("--provider", default="aws", help="Metadata provider name")
    parser.add_argument("--output-dir", default="artifacts/reports")
    parser.add_argument("--json-output", default="cloudspecter-comparison.json")
    parser.add_argument("--markdown-output", default="cloudspecter-comparison.md")
    parser.add_argument("--html-output", default="cloudspecter-comparison.html")
    parser.add_argument("--pdf-output", default="cloudspecter-comparison.pdf")
    return parser


def _build_assess_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--base-url", required=True, help="Base URL of the metadata service")
    parser.add_argument("--provider", default="aws", help="Metadata provider name")
    parser.add_argument("--label", default="lab", help="Scenario label")
    parser.add_argument("--output-dir", default="artifacts/reports")
    parser.add_argument("--json-output", default="cloudspecter-assessment.json")
    parser.add_argument("--markdown-output", default="cloudspecter-assessment.md")
    parser.add_argument("--html-output", default="cloudspecter-assessment.html")
    parser.add_argument("--pdf-output", default="cloudspecter-assessment.pdf")
    return parser


def _build_audit_parser(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    parser.add_argument("--region", default="us-east-1", help="AWS region to audit")
    parser.add_argument("--endpoint-url", default=None, help="Optional LocalStack endpoint URL")
    parser.add_argument("--source-label", default="authorized_aws", help="Label for the audit source")
    parser.add_argument("--output-dir", default="artifacts/reports")
    parser.add_argument("--json-output", default="cloudspecter-aws-audit.json")
    parser.add_argument("--markdown-output", default="cloudspecter-aws-audit.md")
    parser.add_argument("--html-output", default="cloudspecter-aws-audit.html")
    parser.add_argument("--pdf-output", default="cloudspecter-aws-audit.pdf")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    service = MetadataAssessmentService()
    auditor = AwsAuditorEngine()

    if argv and argv[0] in {"compare", "assess", "audit"}:
        command = argv.pop(0)
    else:
        command = "compare"

    parser = argparse.ArgumentParser(description="CloudSpecter defensive metadata assessment toolkit")
    if command == "compare":
        parser = _build_compare_parser(parser)
        args = parser.parse_args(argv)
        report = service.compare(
            vulnerable_endpoint=args.vulnerable_base_url,
            protected_endpoint=args.protected_base_url,
            provider_name=args.provider,
        ).to_dict()
        output_dir = Path(args.output_dir)
        json_path = save_report(report, output_dir / args.json_output)
        md_path = save_markdown(report, output_dir / args.markdown_output)
        html_path = save_html(report, output_dir / args.html_output)
        pdf_path = save_pdf(report, output_dir / args.pdf_output)
        print(json.dumps({"json": str(json_path), "markdown": str(md_path), "html": str(html_path), "pdf": str(pdf_path)}, indent=2))
        return 0

    if command == "audit":
        parser = _build_audit_parser(parser)
        args = parser.parse_args(argv)
        report = auditor.audit(region_name=args.region, endpoint_url=args.endpoint_url, source_label=args.source_label).to_dict()
        output_dir = Path(args.output_dir)
        json_path = save_report(report, output_dir / args.json_output)
        md_path = save_markdown(report, output_dir / args.markdown_output)
        html_path = save_html(report, output_dir / args.html_output)
        pdf_path = save_pdf(report, output_dir / args.pdf_output)
        print(json.dumps({"json": str(json_path), "markdown": str(md_path), "html": str(html_path), "pdf": str(pdf_path)}, indent=2))
        return 0

    parser = _build_assess_parser(parser)
    args = parser.parse_args(argv)
    report = service.assess(endpoint=args.base_url, provider_name=args.provider, label=args.label).to_dict()
    output_dir = Path(args.output_dir)
    json_path = save_report(report, output_dir / args.json_output)
    md_path = save_markdown(report, output_dir / args.markdown_output)
    html_path = save_html(report, output_dir / args.html_output)
    pdf_path = save_pdf(report, output_dir / args.pdf_output)
    print(json.dumps({"json": str(json_path), "markdown": str(md_path), "html": str(html_path), "pdf": str(pdf_path)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())