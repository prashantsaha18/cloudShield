"""
CloudShield AI - Incident Report Generator
Produces SOC-style incident reports (structured data + downloadable PDF)
for High/Critical severity events.
"""

import io
from datetime import datetime
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

RECOMMENDED_ACTIONS = {
    "DDoS": [
        "Block or rate-limit the identified source IP ranges at the edge/firewall.",
        "Enable upstream DDoS scrubbing or CDN-based mitigation if available.",
        "Activate connection rate limiting on affected services.",
        "Monitor bandwidth utilization for sustained anomalies.",
    ],
    "DoS": [
        "Apply rate limiting on the targeted service or endpoint.",
        "Block the offending source IP at the firewall.",
        "Review service resource limits (connections, threads) for resilience.",
        "Monitor for repeat attempts from the same source.",
    ],
    "Brute Force": [
        "Lock or temporarily disable the targeted account(s).",
        "Enforce account lockout / exponential backoff after failed attempts.",
        "Require multi-factor authentication on affected accounts.",
        "Block the source IP after repeated failed authentication attempts.",
    ],
    "Port Scan": [
        "Block the scanning source IP at the perimeter firewall.",
        "Review exposed ports and close any that are unnecessary.",
        "Enable intrusion detection alerts for sequential port access patterns.",
    ],
    "SQL Injection": [
        "Block the source IP and review affected application logs.",
        "Apply parameterized queries / input sanitization at the application layer.",
        "Deploy or update WAF rules targeting SQL injection patterns.",
        "Audit the targeted database for unauthorized access or data exfiltration.",
    ],
    "Botnet": [
        "Isolate and inspect the affected host(s) for malware/C2 implants.",
        "Block known command-and-control destination IPs.",
        "Run endpoint detection and response (EDR) scans on affected assets.",
        "Reset credentials on affected systems.",
    ],
    "Malware": [
        "Isolate the affected asset from the network immediately.",
        "Run a full endpoint antivirus/EDR scan and remove identified payloads.",
        "Review recent file and process activity on the affected host.",
        "Patch the vulnerability believed to have enabled infection.",
    ],
    "Phishing": [
        "Block the malicious sender domain / URL at the email gateway.",
        "Notify affected users and force credential resets if links were clicked.",
        "Search mail logs for other recipients of the same campaign.",
        "Conduct phishing-awareness refresher training.",
    ],
    "Unknown Threat": [
        "Escalate to a senior analyst for manual triage.",
        "Isolate the affected asset as a precaution pending investigation.",
        "Capture full packet/log context for forensic review.",
        "Update detection rules once the threat is characterized.",
    ],
}


def generate_incident_records(results_df: pd.DataFrame, scan_id: int, min_severity="High") -> list:
    """
    Build structured incident records for High/Critical events.
    Groups by (attack_type, severity) to avoid one incident per row on
    large datasets, which would be unusable.
    """
    severity_order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    threshold = severity_order.get(min_severity, 2)

    flagged = results_df[results_df["predicted_label"] == "Attack"].copy()
    flagged = flagged[flagged["severity"].map(lambda s: severity_order.get(s, 0)) >= threshold]

    if flagged.empty:
        return []

    incidents = []
    grouped = flagged.groupby(["attack_type_predicted", "severity"])
    counter = 1
    for (attack_type, severity), group in grouped:
        affected_assets = sorted(group["destination_ip"].unique().tolist())[:10]
        source_ips = sorted(group["source_ip"].unique().tolist())[:10]
        incident_id = f"INC-{datetime.now().year}-{scan_id:04d}-{counter:03d}"
        counter += 1
        incidents.append({
            "incident_id": incident_id,
            "threat_type": attack_type,
            "severity": severity,
            "event_count": int(len(group)),
            "affected_assets": affected_assets,
            "source_ips": source_ips,
            "avg_threat_score": round(float(group["threat_score"].mean()), 2),
            "recommended_actions": RECOMMENDED_ACTIONS.get(attack_type, RECOMMENDED_ACTIONS["Unknown Threat"]),
            "first_seen": str(group["timestamp"].min()),
            "last_seen": str(group["timestamp"].max()),
        })

    # Sort critical first
    incidents.sort(key=lambda x: severity_order.get(x["severity"], 0), reverse=True)
    return incidents


def build_incident_pdf(incidents: list, dataset_name: str, analyst_name: str, summary_metrics: dict) -> bytes:
    """Render incidents into a professional SOC-style PDF report. Returns PDF bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=18 * mm, bottomMargin=18 * mm, leftMargin=18 * mm, rightMargin=18 * mm,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleCustom", parent=styles["Title"], fontSize=20, textColor=colors.HexColor("#0B1E3A"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "Subtitle", parent=styles["Normal"], fontSize=10, textColor=colors.HexColor("#5A6B85"),
        spaceAfter=14,
    )
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#0B1E3A"),
                         spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("BodyCustom", parent=styles["Normal"], fontSize=9.5, leading=14)
    meta = ParagraphStyle("Meta", parent=styles["Normal"], fontSize=9, textColor=colors.HexColor("#5A6B85"))

    severity_color = {
        "Critical": colors.HexColor("#E0334E"),
        "High": colors.HexColor("#E07F2E"),
        "Medium": colors.HexColor("#C9A227"),
        "Low": colors.HexColor("#1F9E73"),
    }

    elements = []
    elements.append(Paragraph("CloudShield AI &mdash; Security Incident Report", title_style))
    elements.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; "
        f"Dataset: {dataset_name} &nbsp;|&nbsp; Analyst: {analyst_name}",
        subtitle_style,
    ))

    # Executive summary table
    elements.append(Paragraph("Executive Summary", h2))
    summary_data = [
        ["Total Logs Analyzed", str(summary_metrics.get("total_logs", 0))],
        ["Detected Attacks", str(summary_metrics.get("attack_count", 0))],
        ["Critical Threats", str(summary_metrics.get("critical_count", 0))],
        ["High Severity Threats", str(summary_metrics.get("high_count", 0))],
        ["Total Incidents Reported", str(len(incidents))],
    ]
    summary_table = Table(summary_data, colWidths=[80 * mm, 80 * mm])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F0F3F8")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0B1E3A")),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8DEE9")),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 10))

    if not incidents:
        elements.append(Paragraph("No High or Critical severity incidents were detected in this scan.", body))
    else:
        elements.append(Paragraph("Incident Details", h2))
        for inc in incidents:
            sev_color = severity_color.get(inc["severity"], colors.grey)
            elements.append(Spacer(1, 6))
            header_table = Table(
                [[Paragraph(f"<b>{inc['incident_id']}</b>", body),
                  Paragraph(f"<font color='{sev_color.hexval()}'><b>{inc['severity'].upper()}</b></font>", body)]],
                colWidths=[130 * mm, 30 * mm],
            )
            header_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F7F9FC")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ]))
            elements.append(header_table)

            details = [
                f"<b>Threat Type:</b> {inc['threat_type']}",
                f"<b>Event Count:</b> {inc['event_count']} &nbsp;&nbsp; <b>Avg Threat Score:</b> {inc['avg_threat_score']}/100",
                f"<b>First Seen:</b> {inc['first_seen']} &nbsp;&nbsp; <b>Last Seen:</b> {inc['last_seen']}",
                f"<b>Source IP(s):</b> {', '.join(inc['source_ips'])}",
                f"<b>Affected Assets:</b> {', '.join(inc['affected_assets'])}",
            ]
            for d in details:
                elements.append(Paragraph(d, body))

            elements.append(Paragraph("<b>Recommended Actions:</b>", body))
            for i, action in enumerate(inc["recommended_actions"], 1):
                elements.append(Paragraph(f"{i}. {action}", body))
            elements.append(Spacer(1, 8))

    elements.append(Spacer(1, 14))
    elements.append(Paragraph(
        "This report was generated automatically by CloudShield AI based on statistical "
        "and machine-learning analysis of the provided log data. Findings should be "
        "validated by a qualified security analyst before remediation action is taken.",
        meta,
    ))

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
