"""
CloudShield AI - Export Center
Provides export utilities for CSV, Excel, JSON, and an executive summary PDF.
All functions return in-memory bytes so Streamlit's download_button can
serve them directly without writing to disk (important for Streamlit
Cloud's read-only/ephemeral filesystem).
"""

import io
import json
from datetime import datetime
import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return df.to_csv(index=False).encode("utf-8")


def to_excel_bytes(df: pd.DataFrame, sheet_name="Scan Results") -> bytes:
    buffer = io.BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name[:31])
    buffer.seek(0)
    return buffer.getvalue()


def to_json_bytes(df: pd.DataFrame) -> bytes:
    records = df.to_dict(orient="records")
    return json.dumps(records, indent=2, default=str).encode("utf-8")


def build_executive_summary_pdf(metrics: dict, dataset_name: str, analyst_name: str) -> bytes:
    """A short, board-room-friendly executive summary PDF (Module 13 bonus feature)."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm, leftMargin=20 * mm, rightMargin=20 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("Title2", parent=styles["Title"], fontSize=18,
                                  textColor=colors.HexColor("#0B1E3A"))
    subtitle_style = ParagraphStyle("Sub2", parent=styles["Normal"], fontSize=10,
                                     textColor=colors.HexColor("#5A6B85"), spaceAfter=16)
    body = ParagraphStyle("Body2", parent=styles["Normal"], fontSize=10.5, leading=16)

    elements = [
        Paragraph("CloudShield AI &mdash; Executive Summary", title_style),
        Paragraph(
            f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} for dataset "
            f"'{dataset_name}' by {analyst_name}",
            subtitle_style,
        ),
    ]

    total = metrics.get("total_logs", 0)
    attacks = metrics.get("attack_count", 0)
    pct = round((attacks / total * 100), 1) if total else 0

    summary_text = (
        f"During this scan, <b>{total}</b> network log events were analyzed. "
        f"<b>{attacks}</b> events ({pct}%) were classified as malicious activity. "
        f"Of these, <b>{metrics.get('critical_count', 0)}</b> were rated Critical severity "
        f"and <b>{metrics.get('high_count', 0)}</b> were rated High severity, requiring "
        f"prompt analyst attention."
    )
    elements.append(Paragraph(summary_text, body))
    elements.append(Spacer(1, 14))

    data = [
        ["Metric", "Value"],
        ["Total Logs Analyzed", str(total)],
        ["Detected Attacks", str(attacks)],
        ["Critical", str(metrics.get("critical_count", 0))],
        ["High", str(metrics.get("high_count", 0))],
        ["Medium", str(metrics.get("medium_count", 0))],
        ["Low", str(metrics.get("low_count", 0))],
    ]
    table = Table(data, colWidths=[90 * mm, 70 * mm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0B1E3A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#D8DEE9")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
    ]))
    elements.append(table)

    doc.build(elements)
    buffer.seek(0)
    return buffer.getvalue()
