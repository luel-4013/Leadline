"""
Leadline - PDF Report Export
Renders a scan report (summary + findings) as a formatted PDF using reportlab.

reportlab is pure Python (no system-level dependencies like wkhtmltopdf or
WeasyPrint's Cairo/Pango stack), so it drops into the existing
python:3.11-slim Docker image with no Dockerfile changes.
"""
from io import BytesIO
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable,
    KeepTogether,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ea580c"),
    "medium": colors.HexColor("#ca8a04"),
    "low": colors.HexColor("#2563eb"),
    "info": colors.HexColor("#6b7280"),
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Findings come from scanned, untrusted web content (headers, JS snippets,
# response bodies, ...) and reportlab's Paragraph text is parsed as a small
# XML-like markup, so anything user/scan-controlled must be escaped before
# being handed to Paragraph() -- otherwise a stray "<script>" in captured
# evidence would be parsed as a tag rather than displayed as text, and could
# raise or mis-render.
def _escape(text: Optional[str], limit: int = 4000) -> str:
    if not text:
        return ""
    text = str(text)[:limit]
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "Brand", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8.5,
        leading=11, textColor=colors.HexColor("#0e7490"), spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=23, leading=27,
        textColor=colors.HexColor("#111827"), spaceAfter=2, alignment=0,
    ))
    styles.add(ParagraphStyle(
        "TargetName", parent=styles["Heading2"], fontSize=13, leading=17,
        textColor=colors.HexColor("#374151"), spaceAfter=1,
    ))
    styles.add(ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"], fontSize=13, leading=16,
        spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#111827"),
        keepWithNext=1,
    ))
    styles.add(ParagraphStyle(
        "FindingTitle", parent=styles["Heading3"], fontSize=10.5, leading=13,
        spaceBefore=0, spaceAfter=1, textColor=colors.HexColor("#111827"),
    ))
    styles.add(ParagraphStyle(
        "Meta", parent=styles["Normal"], textColor=colors.HexColor("#6b7280"),
        fontSize=8.5, leading=11,
    ))
    styles.add(ParagraphStyle(
        "Label", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8,
        leading=10, textColor=colors.HexColor("#4b5563"), spaceBefore=6, spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        "Mono", parent=styles["Normal"], fontName="Courier", fontSize=8.5,
        leading=11, textColor=colors.HexColor("#374151"), wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        "CodeBlock", parent=styles["Normal"], fontName="Courier", fontSize=8.5,
        leading=11, textColor=colors.HexColor("#1f2937"), wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        "TableCell", parent=styles["Normal"], fontSize=8, leading=9.5,
        textColor=colors.HexColor("#374151"),
    ))
    styles.add(ParagraphStyle(
        "TableHead", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=8,
        leading=9.5, textColor=colors.white,
    ))
    styles.add(ParagraphStyle(
        "Confidential", parent=styles["Normal"], fontSize=8, leading=10,
        textColor=colors.HexColor("#991b1b"),
    ))
    styles.add(ParagraphStyle(
        "Disclosure", parent=styles["Normal"], fontSize=8.5, leading=11.5,
        textColor=colors.HexColor("#4b5563"),
    ))
    return styles


def _code_block(text: str, styles, limit: int = 2000) -> Table:
    """Render untrusted evidence in a padded, wrapped box.

    ReportLab Paragraph backgrounds with ``borderPadding`` can paint over the
    preceding flowable (the old "Evidence:" overlap). A one-cell table owns
    its padding, so the label and the evidence text can never collide.
    """
    cell = Paragraph(_escape(text, limit), styles["CodeBlock"])
    block = Table([[cell]], colWidths=[6.95 * inch])
    block.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, colors.HexColor("#9ca3af")),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return block


def _severity_badge_style(styles, severity: str) -> ParagraphStyle:
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"])
    return ParagraphStyle(
        f"severity_{severity}", parent=styles["Normal"], textColor=colors.white,
        backColor=color, alignment=TA_CENTER, fontSize=8, leading=14,
    )


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#e5e7eb"))
    canvas.setLineWidth(0.5)
    canvas.line(0.75 * inch, 0.62 * inch, letter[0] - 0.75 * inch, 0.62 * inch)

    x = 0.75 * inch
    canvas.setFont("Helvetica-Bold", 7.5)
    canvas.setFillColor(colors.HexColor("#b91c1c"))
    canvas.drawString(x, 0.46 * inch, "CONFIDENTIAL")
    x += canvas.stringWidth("CONFIDENTIAL", "Helvetica-Bold", 7.5) + 9

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#9ca3af"))
    label = getattr(
        doc, "leadline_footer",
        "Generated by Leadline -- for authorized security assessments only",
    )
    page_label = f"Page {doc.page}"
    max_width = (
        letter[0] - 1.5 * inch
        - (x - 0.75 * inch)
        - canvas.stringWidth(page_label, "Helvetica", 7.5)
        - 12
    )
    while label and canvas.stringWidth(label, "Helvetica", 7.5) > max_width:
        label = label[:-1]
    canvas.drawString(x, 0.46 * inch, label)
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.46 * inch, page_label)
    canvas.restoreState()


def generate_report_pdf(
    *,
    scan_id: int,
    target_name: str,
    target_url: str,
    status: str,
    created_at: Optional[datetime],
    completed_at: Optional[datetime],
    summary: Dict[str, int],
    highlights: Optional[Dict[str, Any]],
    phases: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> bytes:
    """
    Build a PDF recon report and return it as raw bytes.

    summary: matches ReportSummary's fields (total_endpoints, api_routes, ...)
    highlights: matches ReportHighlights (technologies, headers, DNS/WHOIS/
    geolocation, open ports) -- may be None/empty for older scans run before
    this existed.
    phases: list of {phase_name, phase_order, status, findings_count}
    findings: list of {finding_type, severity, title, description, location,
               evidence, remediation} -- rendered most-severe first.
    """
    highlights = highlights or {}
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        title=f"Leadline Report - {target_name}",
        author="Leadline",
        subject="CONFIDENTIAL - Attack surface assessment report",
        keywords="confidential, security assessment, attack surface, Leadline",
    )
    doc.leadline_footer = f"Leadline | {target_url or target_name} | Scan #{scan_id}"
    styles = _build_styles()
    story = []

    # --- Header -------------------------------------------------------
    story.append(Paragraph("LEADLINE", styles["Brand"]))
    story.append(Paragraph("Attack Surface Report", styles["ReportTitle"]))
    story.append(Paragraph(_escape(target_name, 200), styles["TargetName"]))
    story.append(Paragraph(_escape(target_url, 300), styles["Meta"]))
    story.append(Spacer(1, 10))

    meta_rows = [
        ["Scan ID", f"#{scan_id}"],
        ["Status", status],
        ["Started", created_at.strftime("%Y-%m-%d %H:%M UTC") if created_at else "-"],
        ["Completed", completed_at.strftime("%Y-%m-%d %H:%M UTC") if completed_at else "-"],
        ["Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")],
    ]
    meta_table = Table(meta_rows, colWidths=[1.5 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))

    # --- Confidentiality banner -----------------------------------------
    confidential_notice = Table(
        [[Paragraph(
            "<b>CONFIDENTIAL</b> &nbsp;|&nbsp; This report contains security-sensitive "
            "information about the assessed target. Distribution is limited to "
            "authorized recipients.",
            styles["Confidential"],
        )]],
        colWidths=[6.95 * inch],
    )
    confidential_notice.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef2f2")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#fecaca")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#dc2626")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(Spacer(1, 10))
    story.append(confidential_notice)

    # --- Overall Risk -- headline number before any other detail ------
    risk_level = (summary.get("risk_level") or "minimal").upper()
    risk_score = summary.get("risk_score", 0)
    risk_colors = {
        "CRITICAL": colors.HexColor("#dc2626"), "HIGH": colors.HexColor("#ea580c"),
        "MEDIUM": colors.HexColor("#ca8a04"), "LOW": colors.HexColor("#2563eb"),
        "MINIMAL": colors.HexColor("#6b7280"),
    }
    risk_color = risk_colors.get(risk_level, colors.HexColor("#6b7280"))
    score_style = ParagraphStyle(
        "RiskScore", parent=styles["Title"], fontSize=30, leading=32,
        textColor=risk_color, alignment=0, spaceAfter=0,
    )
    level_style = ParagraphStyle(
        "RiskLevel", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10,
        leading=13, textColor=risk_color,
    )
    risk_table = Table(
        [[
            Paragraph(str(risk_score), score_style),
            Paragraph(
                f"{risk_level}<br/>"
                "<font size='8' color='#6b7280'>Derived from the highest-severity "
                "findings present, not just total finding count.</font>",
                level_style,
            ),
        ]],
        colWidths=[1.0 * inch, 6.0 * inch],
    )
    risk_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("LINEBEFORE", (0, 0), (0, -1), 4, risk_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (0, 0), 12),
        ("LEFTPADDING", (1, 0), (1, 0), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(Spacer(1, 10))
    story.append(risk_table)
    story.append(Spacer(1, 8))

    # --- Summary --------------------------------------------------------
    story.append(Paragraph("Summary", styles["SectionHeading"]))
    summary_fields = [
        ("Endpoints", summary.get("total_endpoints", 0)),
        ("API Routes (observed)", summary.get("api_routes", 0)),
        ("API Candidates (inferred)", summary.get("api_candidates", 0)),
        ("Authentication Mechanisms", summary.get("authentication_mechanisms", 0)),
        ("Debug Interfaces", summary.get("debug_interfaces", 0)),
        ("Suspicious Parameters", summary.get("suspicious_parameters", 0)),
        ("Possible Vulnerabilities", summary.get("possible_vulns", 0)),
        ("Missing Controls", summary.get("missing_controls", 0)),
        ("Open Ports Found", summary.get("open_ports_found", 0)),
        ("High-Risk Open Ports", summary.get("high_risk_ports", 0)),
        ("CVE Candidates", summary.get("cves_found", 0)),
        ("Verified CVEs", summary.get("verified_cves", 0)),
        ("Critical CVE Candidates", summary.get("critical_cves", 0)),
    ]
    sum_rows = [[label, str(value)] for label, value in summary_fields]
    sum_table = Table(sum_rows, colWidths=[3 * inch, 3 * inch])
    sum_table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#374151")),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    story.append(sum_table)

    # --- Highlights: technologies, headers, DNS/WHOIS/geolocation, ports ---
    has_highlights = any([
        highlights.get("technologies"), highlights.get("response_headers"),
        highlights.get("security_headers_present"), highlights.get("security_headers_missing"),
        highlights.get("resolved_ips"), highlights.get("geolocation"),
        highlights.get("whois"), highlights.get("open_ports"),
    ])
    if has_highlights:
        story.append(Paragraph("Highlights", styles["SectionHeading"]))

        if highlights.get("technologies"):
            story.append(Paragraph(f"<b>Technologies:</b> {_escape(', '.join(highlights['technologies']), 500)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        if highlights.get("cdn_waf"):
            story.append(Paragraph(f"<b>CDN/WAF detected:</b> {_escape(', '.join(highlights['cdn_waf']), 300)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        if highlights.get("security_headers_present") or highlights.get("security_headers_missing"):
            present = ', '.join(highlights.get("security_headers_present") or []) or "none"
            missing = ', '.join(highlights.get("security_headers_missing") or []) or "none"
            story.append(Paragraph(f"<b>Security headers present:</b> {_escape(present, 500)}", styles["Normal"]))
            story.append(Paragraph(f"<b>Security headers missing:</b> {_escape(missing, 500)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        if highlights.get("resolved_ips") or highlights.get("hostnames"):
            if highlights.get("resolved_ips"):
                story.append(Paragraph(f"<b>Resolved IPs:</b> {_escape(', '.join(highlights['resolved_ips']), 300)}", styles["Normal"]))
            if highlights.get("hostnames"):
                story.append(Paragraph(f"<b>Hostnames (reverse DNS):</b> {_escape(', '.join(highlights['hostnames']), 300)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        geo = highlights.get("geolocation") or {}
        if geo.get("country"):
            geo_line = f"{geo.get('city', '')}, {geo['country']} -- {geo.get('isp') or geo.get('org') or 'unknown ISP/org'} ({geo.get('asn', 'unknown ASN')})"
            story.append(Paragraph(f"<b>Geolocation:</b> {_escape(geo_line, 300)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        whois_parsed = (highlights.get("whois") or {}).get("parsed") or {}
        if whois_parsed.get("registrar"):
            whois_line = f"Registrar: {whois_parsed.get('registrar', 'unknown')}, Created: {whois_parsed.get('creation_date', 'unknown')}, Expires: {whois_parsed.get('expiration_date', 'unknown')}"
            story.append(Paragraph(f"<b>WHOIS:</b> {_escape(whois_line, 400)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        if highlights.get("dnssec_enabled") is not None:
            dnssec_line = "Enabled" if highlights["dnssec_enabled"] else "Not enabled"
            story.append(Paragraph(f"<b>DNSSEC:</b> {dnssec_line}", styles["Normal"]))
            story.append(Spacer(1, 4))

        ip_rep = highlights.get("ip_reputation") or {}
        if ip_rep.get("listed") is not None:
            rep_line = ("LISTED -- " + ", ".join(ip_rep.get("reasons", []))) if ip_rep.get("listed") else "Clean (Spamhaus ZEN)"
            story.append(Paragraph(f"<b>IP Reputation:</b> {_escape(rep_line, 300)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        if highlights.get("subdomains"):
            subs = highlights["subdomains"]
            subs_line = ', '.join(subs[:50]) + (f" (+{len(subs) - 50} more)" if len(subs) > 50 else "")
            story.append(Paragraph(f"<b>Subdomains found ({len(subs)}):</b> {_escape(subs_line, 1500)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        if highlights.get("open_ports"):
            head = styles["TableHead"]
            cell = styles["TableCell"]
            port_rows = [[
                Paragraph("Port", head), Paragraph("Service", head), Paragraph("Detail", head)
            ]]
            for port, info in highlights["open_ports"].items():
                info = info or {}
                detail = info.get("version_guess") or (info.get("tls") or {}).get("subject_cn") or (info.get("banner") or "")
                port_rows.append([
                    Paragraph(_escape(str(port), 20), cell),
                    Paragraph(_escape(info.get("service", ""), 40), cell),
                    Paragraph(_escape(detail, 160), cell),
                ])
            port_table = Table(port_rows, colWidths=[0.7 * inch, 1.4 * inch, 4.9 * inch])
            port_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ]))
            story.append(port_table)
            story.append(Spacer(1, 4))

        if highlights.get("api_documentation"):
            story.append(Paragraph(f"<b>Exposed API documentation:</b> {_escape(', '.join(highlights['api_documentation']), 500)}", styles["Normal"]))
            story.append(Spacer(1, 4))

        if highlights.get("url_parameters"):
            params = highlights["url_parameters"]
            story.append(Paragraph(f"<b>URL/form parameters seen ({len(params)}):</b> {_escape(', '.join(params[:80]), 800)}", styles["Normal"]))
            story.append(Spacer(1, 4))

    # --- CVE correlations -- dedicated section given how central this is
    # for a pentester/SOC audience deciding what to prioritize ------------
    cve_matches = highlights.get("cve_matches") or []
    cve_note = highlights.get("cve_lookup_note")
    if cve_matches or cve_note:
        story.append(PageBreak())
        story.append(Paragraph(f"CVE Correlations ({len(cve_matches)})", styles["SectionHeading"]))
        story.append(Paragraph(
            "CPE-range rows were checked against the observed version. Keyword-only rows are "
            "candidates and require manual confirmation. ExploitDB links are search queries, "
            "not embedded exploit content.",
            styles["Meta"]
        ))
        if cve_note:
            note_style = ParagraphStyle(
                "CveNote", parent=styles["Normal"], textColor=colors.HexColor("#92400e"),
                backColor=colors.HexColor("#fef3c7"), borderPadding=6, fontSize=9,
            )
            story.append(Spacer(1, 6))
            story.append(Paragraph(f"NOTE: {_escape(cve_note, 500)}", note_style))
        story.append(Spacer(1, 8))
        if cve_matches:
            head = styles["TableHead"]
            cell = styles["TableCell"]
            cve_rows = [[
                Paragraph("CVE", head), Paragraph("Severity", head),
                Paragraph("Score", head), Paragraph("Product / Version", head),
                Paragraph("Applicability", head),
            ]]
            for cve in cve_matches:
                cve_rows.append([
                    Paragraph(_escape(cve.get("cve_id", ""), 40), cell),
                    Paragraph(_escape((cve.get("cvss_severity") or "unscored").upper(), 20), cell),
                    Paragraph(_escape(str(cve.get("cvss_score", "-")), 10), cell),
                    Paragraph(_escape(f"{cve.get('product', '')} {cve.get('version', '')}".strip(), 120), cell),
                    Paragraph(
                        "CPE range" if cve.get("applicability_verified") else "keyword only",
                        cell,
                    ),
                ])
            cve_table = Table(
                cve_rows,
                colWidths=[1.15 * inch, 0.85 * inch, 0.55 * inch, 3.1 * inch, 1.35 * inch],
            )
            cve_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ]))
            story.append(cve_table)
            story.append(Spacer(1, 10))

        for cve in cve_matches:
            title = f"{cve.get('cve_id', '')} -- {cve.get('product', '')} {cve.get('version', '')}"
            story.append(Paragraph(_escape(title, 200), styles["FindingTitle"]))
            if cve.get("description"):
                story.append(Paragraph(_escape(cve["description"], 800), styles["Normal"]))
                story.append(Spacer(1, 4))
            links = f"NVD: {cve.get('nvd_url', '')}  |  ExploitDB search: {cve.get('exploitdb_search_url', '')}"
            story.append(Paragraph(_escape(links, 400), styles["Mono"]))
            story.append(Spacer(1, 8))

    # --- Phase completion ------------------------------------------------
    story.append(Paragraph("Reconnaissance Phases", styles["SectionHeading"]))
    head = styles["TableHead"]
    cell = styles["TableCell"]
    phase_rows = [[
        Paragraph("#", head), Paragraph("Phase", head),
        Paragraph("Status", head), Paragraph("Findings", head),
    ]]
    for p in sorted(phases, key=lambda x: x.get("phase_order", 0)):
        phase_rows.append([
            Paragraph(_escape(str(p.get("phase_order", "")), 5), cell),
            Paragraph(_escape((p.get("phase_name", "") or "").replace("_", " ").title(), 80), cell),
            Paragraph(_escape(p.get("status", ""), 20), cell),
            Paragraph(_escape(str(p.get("findings_count", 0)), 10), cell),
        ])
    phase_table = Table(
        phase_rows,
        colWidths=[0.5 * inch, 4.0 * inch, 1.5 * inch, 1.0 * inch],
    )
    phase_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    story.append(phase_table)

    # --- Findings ---------------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph(f"Findings ({len(findings)})", styles["SectionHeading"]))

    if not findings:
        story.append(Paragraph("No findings were recorded for this scan.", styles["Normal"]))
    else:
        ordered = sorted(
            findings,
            key=lambda f: SEVERITY_ORDER.index(f["severity"])
            if f.get("severity") in SEVERITY_ORDER else len(SEVERITY_ORDER),
        )
        severity_line = "   ·   ".join(
            f"{severity.upper()} {sum(1 for f in findings if (f.get('severity') or 'info').lower() == severity)}"
            for severity in SEVERITY_ORDER
            if any((f.get("severity") or "info").lower() == severity for f in findings)
        )
        if severity_line:
            story.append(Paragraph(_escape(severity_line, 200), styles["Meta"]))
            story.append(Spacer(1, 4))

        for f in ordered:
            severity = (f.get("severity") or "info").lower()
            badge = Paragraph(severity.upper()[:12], _severity_badge_style(styles, severity))
            title = Paragraph(_escape(f.get("title") or f.get("finding_type") or "Finding", 300), styles["FindingTitle"])

            header_table = Table([[badge, title]], colWidths=[0.85 * inch, 6.15 * inch])
            header_table.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (0, 0), 0),
                ("LEFTPADDING", (1, 0), (1, 0), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))

            meta_bits = []
            finding_type = (f.get("finding_type") or "").replace("_", " ").strip()
            if finding_type:
                meta_bits.append(finding_type.title())
            triage = (f.get("triage_status") or "open").replace("_", " ")
            if triage != "open":
                meta_bits.append(f"Triage: {triage}")
            head = [header_table]
            if meta_bits:
                head.append(Paragraph(_escape(" · ".join(meta_bits), 200), styles["Meta"]))
            if f.get("location"):
                head.append(Paragraph(_escape(f["location"], 300), styles["Mono"]))
            if f.get("description"):
                # Keep the title, location, and description on one page; an
                # orphaned finding heading at the bottom of a page reads as a
                # formatting bug. Evidence is allowed to start a new page.
                head.append(Paragraph(_escape(f["description"], 2000), styles["Normal"]))
            story.append(KeepTogether(head))
            story.append(Spacer(1, 4))

            if f.get("evidence"):
                story.append(Paragraph("Evidence", styles["Label"]))
                story.append(_code_block(f["evidence"], styles, 2000))
            if f.get("remediation"):
                story.append(Paragraph("Remediation", styles["Label"]))
                story.append(Paragraph(_escape(f["remediation"]), styles["Normal"]))

            story.append(Spacer(1, 8))
            story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
            story.append(Spacer(1, 6))

    # --- Endpoints appendix ------------------------------------------------
    endpoints = sorted({f["location"] for f in findings if f.get("location")})
    if endpoints:
        story.append(Spacer(1, 14))
        story.append(Paragraph(f"Discovered Endpoints ({len(endpoints)})", styles["SectionHeading"]))
        for ep in endpoints[:200]:
            story.append(Paragraph(_escape(ep, 300), styles["Mono"]))

    # --- Confidentiality and authorized-use disclosure --------------------
    disclosure_box = Table(
        [[Paragraph(
            "<b>CONFIDENTIAL.</b> This report contains security-sensitive information "
            "about the assessed target. It was generated by Leadline for an authorized "
            "security assessment and is intended only for the target owner and "
            "explicitly authorized recipients. Do not publish, redistribute, or "
            "disclose this document without written permission.<br/><br/>"
            "Findings are based on automated reconnaissance and may include false "
            "positives. CVE candidates marked <i>keyword only</i> are unverified and "
            "must be manually validated before being treated as confirmed "
            "vulnerabilities. Scan only systems you own or have explicit permission "
            "to assess.<br/><br/>"
            f"<font size='7.5' color='#6b7280'>Report reference: Scan #{scan_id} · "
            f"{_escape(target_url or target_name, 300)}</font>",
            styles["Disclosure"],
        )]],
        colWidths=[6.95 * inch],
    )
    disclosure_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f9fafb")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
        ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor("#9ca3af")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(Spacer(1, 20))
    story.append(KeepTogether([
        Paragraph("Confidentiality & Authorized Use", styles["SectionHeading"]),
        disclosure_box,
    ]))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
