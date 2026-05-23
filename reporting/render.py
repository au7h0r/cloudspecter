from __future__ import annotations

import io
import html
import json
from collections import Counter
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


def render_html(report: dict[str, Any]) -> str:
    if "scope" in report and "findings" in report:
        return _render_aws_audit_html(report)
    return _html_page("CloudSpecter Report", [
        _section("Executive Summary", [_empty_state("HTML rendering is available for AWS audit reports.")]),
        _section("Findings", [_empty_state("No HTML template is defined for this report shape yet.")]),
        _section("Risk Ratings", [_empty_state("No risk ratings available.")]),
        _section("MITRE Mapping", [_empty_state("No MITRE mappings available.")]),
        _section("Screenshots", [_empty_state("No screenshots were attached.")]),
        _section("Remediation", [_empty_state("No remediation items were generated.")]),
    ])


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


def _render_aws_audit_html(report: dict[str, Any]) -> str:
    scope = report["scope"]
    findings = report.get("findings", [])
    sections = [
        _section(
            "Executive Summary",
            [
                _kv_table(
                    [
                        ("Generated at", report["generated_at"]),
                        ("Account", scope.get("account_id") or "unknown"),
                        ("Region", scope["region"]),
                        ("Source", scope["source"]),
                        ("Risk score", f"{report['risk_score']} ({report['risk_level']})"),
                    ]
                )
            ],
        ),
        _section("Visualizations", [_visualizations_section(findings)]),
        _section(
            "Findings",
            [
                _table(
                    ["Finding", "Resource", "Severity", "CVSS", "Exploitability"],
                    [
                        [
                            item["finding"]["finding"],
                            f"{item['resource_type']}:{item['resource_id']}",
                            item["finding"]["severity"],
                            item["finding"]["cvss"],
                            item["finding"]["exploitability"],
                        ]
                        for item in findings
                    ],
                )
                if findings
                else _empty_state("No findings were generated for this audit."),
            ],
        ),
        _section(
            "Risk Ratings",
            [
                _table(["Severity", "Count"], _severity_rows(findings))
                if findings
                else _empty_state("No risk ratings available."),
            ],
        ),
        _section(
            "MITRE Mapping",
            [
                _table(
                    ["Finding", "MITRE", "Resource"],
                    [
                        [item["finding"]["finding"], item["finding"]["mitre"], f"{item['resource_type']}:{item['resource_id']}" ]
                        for item in findings
                    ],
                )
                if findings
                else _empty_state("No MITRE mappings to display."),
            ],
        ),
        _section("Screenshots", [_screenshot_section(report)]),
        _section("Remediation", [_bullet_list(report.get("remediation", []), empty_message="No remediation items were generated.")]),
    ]
    return _html_page("CloudSpecter AWS Audit Report", sections)


def save_markdown(report: dict[str, Any], output_path: str | Path) -> Path:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(render_markdown(report), encoding="utf-8")
    return output_file


def save_html(report: dict[str, Any], output_path: str | Path) -> Path:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(render_html(report), encoding="utf-8")
    return output_file


def render_pdf(report: dict[str, Any], engine: str = "auto") -> bytes:
    last_error: Exception | None = None

    if engine in {"auto", "weasyprint"}:
        try:
            from weasyprint import HTML

            return HTML(string=render_html(report)).write_pdf()
        except Exception as exc:  # pragma: no cover - exercised when optional deps are missing
            last_error = exc
            if engine == "weasyprint":
                raise

    if engine in {"auto", "reportlab"}:
        try:
            return _render_pdf_reportlab(report)
        except Exception as exc:  # pragma: no cover - exercised when optional deps are missing
            last_error = exc
            if engine == "reportlab":
                raise

    raise RuntimeError("PDF rendering requires WeasyPrint or ReportLab to be installed") from last_error


def save_pdf(report: dict[str, Any], output_path: str | Path, engine: str = "auto") -> Path:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_bytes(render_pdf(report, engine=engine))
    return output_file


def save_report(report: dict[str, Any], output_path: str | Path) -> Path:
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    return output_file


def load_report(report_path: str | Path) -> dict[str, Any]:
    return json.loads(Path(report_path).read_text(encoding="utf-8"))


def _render_pdf_reportlab(report: dict[str, Any]) -> bytes:
    if "scope" not in report or "findings" not in report:
        return _render_pdf_reportlab_text("CloudSpecter Report", render_markdown(report).splitlines())

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    page_width, page_height = A4
    document = canvas.Canvas(buffer, pagesize=A4)
    left_margin = 18 * mm
    right_margin = 18 * mm
    top_margin = 18 * mm
    bottom_margin = 18 * mm
    usable_width = page_width - left_margin - right_margin
    y_position = page_height - top_margin

    document.setTitle("CloudSpecter AWS Audit Report")
    document.setAuthor("CloudSpecter")

    def new_page() -> None:
        nonlocal y_position
        document.showPage()
        y_position = page_height - top_margin

    def draw_text(lines: list[str], *, font_name: str = "Helvetica", font_size: int = 10, leading: int = 13) -> None:
        nonlocal y_position
        document.setFont(font_name, font_size)
        for line in lines:
            wrapped = _wrap_pdf_line(line, usable_width, font_name, font_size)
            for chunk in wrapped:
                if y_position < bottom_margin + leading:
                    new_page()
                    document.setFont(font_name, font_size)
                document.drawString(left_margin, y_position, chunk)
                y_position -= leading

    def draw_section(title: str, lines: list[str]) -> None:
        nonlocal y_position
        if y_position < bottom_margin + 40:
            new_page()
        document.setFillColor(colors.HexColor("#0f766e"))
        document.setFont("Helvetica-Bold", 14)
        document.drawString(left_margin, y_position, title)
        y_position -= 18
        document.setFillColor(colors.black)
        draw_text(lines)
        y_position -= 10

    draw_section(
        "Executive Summary",
        [
            f"Generated at: {report['generated_at']}",
            f"Account: {report['scope'].get('account_id') or 'unknown'}",
            f"Region: {report['scope']['region']}",
            f"Source: {report['scope']['source']}",
            f"Risk score: {report['risk_score']} ({report['risk_level']})",
        ],
    )

    findings = report.get("findings", [])
    findings_lines = [
        f"- {item['finding']['finding']} | resource: {item['resource_type']}:{item['resource_id']} | severity: {item['finding']['severity']} | cvss: {item['finding']['cvss']} | exploitability: {item['finding']['exploitability']}"
        for item in findings
    ] or ["No findings were generated for this audit."]
    draw_section(
        "Findings",
        findings_lines,
    )

    severity_counts = Counter(item["finding"]["severity"] for item in findings)
    draw_section(
        "Risk Ratings",
        [f"{severity}: {count}" for severity, count in severity_counts.items()] or ["No risk ratings available."],
    )

    draw_section(
        "MITRE Mapping",
        [
            f"- {item['finding']['finding']} -> {item['finding']['mitre']} ({item['resource_type']}:{item['resource_id']})"
            for item in findings
        ] or ["No MITRE mappings to display."],
    )

    screenshots = report.get("screenshots") or report.get("artifacts", {}).get("screenshots") or []
    screenshot_lines = []
    if screenshots:
        for item in screenshots:
            if isinstance(item, dict):
                screenshot_lines.append(f"- {item.get('caption') or item.get('title') or 'Screenshot'}: {item.get('url') or item.get('src') or ''}")
            else:
                screenshot_lines.append(f"- {item}")
    else:
        screenshot_lines.append("No screenshots were attached to this report.")
    draw_section("Screenshots", screenshot_lines)

    remediation = report.get("remediation", [])
    draw_section("Remediation", [f"- {item}" for item in remediation] or ["No remediation items were generated."])

    document.save()
    return buffer.getvalue()


def _render_pdf_reportlab_text(title: str, lines: list[str]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    page_width, page_height = A4
    document = canvas.Canvas(buffer, pagesize=A4)
    left_margin = 18 * mm
    right_margin = 18 * mm
    top_margin = 18 * mm
    bottom_margin = 18 * mm
    usable_width = page_width - left_margin - right_margin
    y_position = page_height - top_margin

    document.setTitle(title)
    document.setAuthor("CloudSpecter")

    def new_page() -> None:
        nonlocal y_position
        document.showPage()
        y_position = page_height - top_margin

    document.setFillColor(colors.HexColor("#0f766e"))
    document.setFont("Helvetica-Bold", 16)
    document.drawString(left_margin, y_position, title)
    y_position -= 22
    document.setFillColor(colors.black)

    for line in lines:
        wrapped_lines = _wrap_pdf_line(line, usable_width, "Helvetica", 10)
        for chunk in wrapped_lines:
            if y_position < bottom_margin + 13:
                new_page()
                document.setFillColor(colors.black)
            document.setFont("Helvetica", 10)
            document.drawString(left_margin, y_position, chunk)
            y_position -= 13

    document.save()
    return buffer.getvalue()


def _wrap_pdf_line(text: str, usable_width: float, font_name: str, font_size: int) -> list[str]:
    from reportlab.pdfbase.pdfmetrics import stringWidth

    if not text:
        return [""]

    words = text.split()
    if not words:
        return [""]

    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        candidate = f"{current} {word}"
        if stringWidth(candidate, font_name, font_size) <= usable_width:
            current = candidate
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def _html_page(title: str, sections: list[str]) -> str:
    body = "\n".join(sections)
    return f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>{html.escape(title)}</title>
  <style>
    :root {{ color-scheme: light; --bg: #f6f4ef; --panel: #ffffff; --text: #1f2933; --muted: #5b6470; --border: #d6d1c7; --accent: #0f766e; --soft: #ecfdf5; }}
    body {{ margin: 0; font-family: Arial, Helvetica, sans-serif; background: linear-gradient(180deg, #f8f5ee 0%, #eef2f7 100%); color: var(--text); }}
    main {{ max-width: 1180px; margin: 0 auto; padding: 32px 20px 56px; }}
    header {{ background: rgba(255,255,255,0.9); border: 1px solid var(--border); border-radius: 20px; padding: 24px 28px; box-shadow: 0 18px 48px rgba(15, 23, 42, 0.08); margin-bottom: 20px; }}
    h1 {{ margin: 0; font-size: clamp(2rem, 4vw, 3rem); letter-spacing: -0.03em; }}
    .subtitle {{ margin-top: 10px; color: var(--muted); }}
    section {{ background: rgba(255,255,255,0.95); border: 1px solid var(--border); border-radius: 18px; padding: 20px 22px; margin: 18px 0; box-shadow: 0 10px 28px rgba(15, 23, 42, 0.05); }}
    section h2 {{ margin: 0 0 14px; font-size: 1.2rem; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ background: #fafafa; font-size: 0.92rem; color: var(--muted); }}
    ul {{ margin: 0; padding-left: 20px; }}
    li {{ margin: 6px 0; }}
    .kv {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }}
    .kv div {{ background: var(--soft); border: 1px solid #d1fae5; border-radius: 14px; padding: 14px 16px; }}
    .kv .key {{ display: block; color: var(--muted); font-size: 0.85rem; margin-bottom: 5px; }}
    .empty {{ color: var(--muted); background: #f8fafc; border: 1px dashed var(--border); border-radius: 14px; padding: 16px; }}
    .visualization-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 14px; }}
    .chart-card {{ border: 1px solid var(--border); border-radius: 16px; background: linear-gradient(180deg, #ffffff 0%, #fafafa 100%); padding: 14px; }}
    .chart-title {{ font-weight: 700; font-size: 1rem; margin-bottom: 4px; }}
    .chart-caption {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 12px; }}
    .chart-svg {{ overflow-x: auto; }}
    .svg-chart {{ width: 100%; height: auto; display: block; }}
    .svg-label {{ fill: #475569; font-size: 12px; dominant-baseline: middle; }}
    .svg-value {{ fill: #0f172a; font-size: 12px; font-weight: 700; dominant-baseline: middle; }}
    .svg-timeline-step {{ fill: #ffffff; font-size: 12px; font-weight: 700; dominant-baseline: middle; }}
    .screenshot-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }}
    .shot {{ border: 1px solid var(--border); border-radius: 16px; overflow: hidden; background: #fff; }}
    .shot img {{ width: 100%; display: block; }}
    .shot .caption {{ padding: 12px 14px; color: var(--muted); font-size: 0.92rem; }}
    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 999px; background: #e2e8f0; color: #334155; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.02em; text-transform: uppercase; }}
  </style>
</head>
<body>
  <main>
    <header>
      <span class=\"badge\">CloudSpecter</span>
      <h1>{html.escape(title)}</h1>
      <div class=\"subtitle\">HTML report generated from the scanner output.</div>
    </header>
    {body}
  </main>
</body>
</html>"""


def _section(title: str, blocks: list[str]) -> str:
    return f"<section><h2>{html.escape(title)}</h2>{''.join(blocks)}</section>"


def _kv_table(items: list[tuple[str, Any]]) -> str:
    cells = []
    for key, value in items:
        cells.append(f"<div><span class=\"key\">{html.escape(str(key))}</span><strong>{html.escape(str(value))}</strong></div>")
    return f"<div class=\"kv\">{''.join(cells)}</div>"


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    header_html = ''.join(f"<th>{html.escape(str(header))}</th>" for header in headers)
    row_html = []
    for row in rows:
        cells = ''.join(f"<td>{html.escape(str(cell))}</td>" for cell in row)
        row_html.append(f"<tr>{cells}</tr>")
    return f"<table><thead><tr>{header_html}</tr></thead><tbody>{''.join(row_html)}</tbody></table>"


def _bullet_list(items: list[Any], empty_message: str = "No items to display.") -> str:
    if not items:
        return _empty_state(empty_message)
    return "<ul>" + ''.join(f"<li>{html.escape(str(item))}</li>" for item in items) + "</ul>"


def _empty_state(message: str) -> str:
    return f"<div class=\"empty\">{html.escape(message)}</div>"


def _screenshot_section(report: dict[str, Any]) -> str:
    screenshots = report.get("screenshots") or report.get("artifacts", {}).get("screenshots") or []
    if not screenshots:
        return _empty_state("No screenshots were attached to this report. Provide screenshot URLs in the report data to render them here.")
    cards = []
    for item in screenshots:
        if isinstance(item, dict):
            src = html.escape(str(item.get("src") or item.get("url") or ""))
            caption = html.escape(str(item.get("caption") or item.get("title") or "Screenshot"))
        else:
            src = html.escape(str(item))
            caption = "Screenshot"
        cards.append(f"<figure class=\"shot\"><img src=\"{src}\" alt=\"{caption}\" /><figcaption class=\"caption\">{caption}</figcaption></figure>")
    return f"<div class=\"screenshot-grid\">{''.join(cards)}</div>"


def _visualizations_section(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return _empty_state("No findings are available to visualize.")

    severity_counts = Counter(item["finding"]["severity"] for item in findings)
    asset_counts = Counter(f"{item['resource_type']}:{item['resource_id']}" for item in findings)
    timeline_items = [item["finding"]["finding"] for item in findings]

    cards = [
        _chart_card(
            "Severity Distribution",
            "Breakdown of findings by severity.",
            _svg_bar_chart(list(severity_counts.items()), width=560, height=240, bar_color="#0f766e"),
        ),
        _chart_card(
            "Attack Timeline",
            "Discovery order of the findings in this report.",
            _svg_timeline_chart(timeline_items),
        ),
        _chart_card(
            "Exploited Assets",
            "Resources affected by findings, grouped by asset.",
            _svg_bar_chart(asset_counts.most_common(8), width=560, height=260, bar_color="#b45309"),
        ),
    ]
    return f"<div class=\"visualization-grid\">{''.join(cards)}</div>"


def _chart_card(title: str, caption: str, svg_markup: str) -> str:
    return (
        f"<div class=\"chart-card\">"
        f"<div class=\"chart-title\">{html.escape(title)}</div>"
        f"<div class=\"chart-caption\">{html.escape(caption)}</div>"
        f"<div class=\"chart-svg\">{svg_markup}</div>"
        f"</div>"
    )


def _svg_bar_chart(items: list[tuple[str, int]], *, width: int, height: int, bar_color: str) -> str:
    if not items:
        return _empty_state("No data available for this chart.")

    left_pad = 150
    right_pad = 26
    top_pad = 18
    bottom_pad = 18
    row_height = max(28, (height - top_pad - bottom_pad) // max(len(items), 1))
    max_value = max(value for _, value in items) or 1
    bar_area = max(width - left_pad - right_pad, 120)

    rows = []
    for index, (label, value) in enumerate(items):
        y = top_pad + index * row_height
        bar_width = max(6, int(bar_area * (value / max_value)))
        rows.append(
            f"<text x=\"0\" y=\"{y + 16}\" class=\"svg-label\">{html.escape(_truncate_label(str(label), 28))}</text>"
            f"<rect x=\"{left_pad}\" y=\"{y + 2}\" width=\"{bar_width}\" height=\"18\" rx=\"9\" fill=\"{bar_color}\" />"
            f"<text x=\"{left_pad + bar_width + 8}\" y=\"{y + 16}\" class=\"svg-value\">{value}</text>"
        )

    return (
        f"<svg viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"Bar chart\" class=\"svg-chart\">"
        f"<rect x=\"0\" y=\"0\" width=\"{width}\" height=\"{height}\" rx=\"16\" fill=\"#fff\" />"
        f"{''.join(rows)}"
        f"</svg>"
    )


def _svg_timeline_chart(items: list[str]) -> str:
    if not items:
        return _empty_state("No findings are available to visualize.")

    width = 760
    height = 240
    top_line = 88
    bottom_text = 188
    left_pad = 46
    right_pad = 46
    usable = width - left_pad - right_pad
    count = len(items)
    step = usable / max(count - 1, 1)
    positions = [left_pad + (step * index if count > 1 else usable / 2) for index in range(count)]

    parts = [f"<line x1=\"{left_pad}\" y1=\"{top_line}\" x2=\"{width - right_pad}\" y2=\"{top_line}\" stroke=\"#94a3b8\" stroke-width=\"4\" stroke-linecap=\"round\" />"]
    for index, (x_pos, item) in enumerate(zip(positions, items), start=1):
        parts.append(
            f"<circle cx=\"{x_pos}\" cy=\"{top_line}\" r=\"14\" fill=\"#0f766e\" />"
            f"<text x=\"{x_pos}\" y=\"{top_line + 5}\" text-anchor=\"middle\" class=\"svg-timeline-step\">{index}</text>"
            f"<text x=\"{x_pos}\" y=\"{bottom_text}\" text-anchor=\"middle\" class=\"svg-label\">{html.escape(_truncate_label(item, 16))}</text>"
        )

    return (
        f"<svg viewBox=\"0 0 {width} {height}\" role=\"img\" aria-label=\"Attack timeline\" class=\"svg-chart\">"
        f"<rect x=\"0\" y=\"0\" width=\"{width}\" height=\"{height}\" rx=\"16\" fill=\"#fff\" />"
        f"{''.join(parts)}"
        f"</svg>"
    )


def _truncate_label(label: str, limit: int) -> str:
    if len(label) <= limit:
        return label
    return label[: max(0, limit - 3)].rstrip() + "..."


def _severity_rows(findings: list[dict[str, Any]]) -> list[list[Any]]:
    counts: dict[str, int] = {}
    for item in findings:
        severity = str(item["finding"].get("severity", "Info"))
        counts[severity] = counts.get(severity, 0) + 1
    ordered = ["Critical", "High", "Medium", "Low", "Info"]
    rows = [[severity, counts[severity]] for severity in ordered if severity in counts]
    for severity, count in counts.items():
        if severity not in ordered:
            rows.append([severity, count])
    return rows
