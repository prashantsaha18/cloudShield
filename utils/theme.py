"""
CloudShield AI - Design System
A console-grade visual identity modeled on real analyst tooling (SIEM/EDR
consoles) rather than a generic dashboard template: dense data panels,
hairline borders, monospace for every data value, and color reserved
strictly for severity signal.

Token system
------------
Surface   #0A0E14  page background
Panel     #11151C  card / table / sidebar surface
Panel-2   #161B24  nested surface (hover, inputs)
Border    #232A35  hairline dividers
Text      #E6E9EF  primary text
Text-dim  #7C8595  secondary / label text
Accent    #2DD4BF  primary actions, links, focus (teal — used sparingly)
Critical  #F0465C
High      #F2994A
Medium    #E8C547
Low       #34D399

Type
----
Display / UI   "Inter"           — nav, headings, body
Data / Mono    "JetBrains Mono"  — IDs, IPs, scores, timestamps, code
"""

import streamlit as st
import plotly.graph_objects as go

# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------
SURFACE = "#0A0E14"
PANEL = "#11151C"
PANEL_2 = "#161B24"
BORDER = "#232A35"
TEXT = "#E6E9EF"
TEXT_DIM = "#7C8595"
TEXT_FAINT = "#4B5263"
ACCENT = "#2DD4BF"
ACCENT_DIM = "#1A2E2C"

SEVERITY_COLORS = {
    "Critical": "#F0465C",
    "High": "#F2994A",
    "Medium": "#E8C547",
    "Low": "#34D399",
}
SEVERITY_BG = {
    "Critical": "#2A1419",
    "High": "#2A1F12",
    "Medium": "#2A2614",
    "Low": "#132A21",
}


def inject_theme():
    st.markdown(f"""
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

        html, body, [class*="css"] {{
            font-family: 'Inter', -apple-system, sans-serif;
        }}

        .stApp {{
            background-color: {SURFACE};
        }}

        .block-container {{
            padding-top: 1.5rem;
            max-width: 1280px;
        }}

        section[data-testid="stSidebar"] {{
            background-color: {PANEL};
            border-right: 1px solid {BORDER};
        }}
        section[data-testid="stSidebar"] .block-container {{
            padding-top: 1rem;
        }}

        h1, h2, h3, h4, h5, p, span, label, div, li {{
            color: {TEXT};
        }}
        h1, h2, h3, h4 {{
            font-weight: 700;
            letter-spacing: -0.01em;
        }}

        .mono {{
            font-family: 'JetBrains Mono', monospace;
        }}

        /* ---------------- Top status bar (signature element) ---------------- */
        .csa-statusbar {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            background-color: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 6px;
            padding: 10px 18px;
            margin-bottom: 20px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: {TEXT_DIM};
            flex-wrap: wrap;
        }}
        .csa-statusbar .csa-status-item {{
            display: flex;
            align-items: center;
            gap: 7px;
            margin-right: 28px;
            white-space: nowrap;
        }}
        .csa-statusbar .csa-dot {{
            width: 7px; height: 7px; border-radius: 50%;
            display: inline-block;
            box-shadow: 0 0 6px currentColor;
        }}

        /* ---------------- Page header ---------------- */
        .csa-page-header {{
            border-bottom: 1px solid {BORDER};
            padding-bottom: 14px;
            margin-bottom: 22px;
        }}
        .csa-page-title {{
            font-size: 22px;
            font-weight: 700;
            color: {TEXT};
            margin: 0;
        }}
        .csa-page-eyebrow {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: {ACCENT};
            margin-bottom: 4px;
            display: block;
        }}
        .csa-page-caption {{
            font-size: 13.5px;
            color: {TEXT_DIM};
            margin-top: 2px;
        }}

        /* ---------------- Panels / cards ---------------- */
        .csa-panel {{
            background-color: {PANEL};
            border: 1px solid {BORDER};
            border-radius: 6px;
            padding: 16px 18px;
            margin-bottom: 14px;
        }}
        .csa-panel-title {{
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.07em;
            color: {TEXT_DIM};
            margin-bottom: 10px;
        }}

        /* ---------------- KPI metric tiles ---------------- */
        .csa-metric {{
            background-color: {PANEL};
            border: 1px solid {BORDER};
            border-left: 3px solid {ACCENT};
            border-radius: 4px;
            padding: 14px 16px;
        }}
        .csa-metric-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.07em;
            color: {TEXT_DIM};
            font-weight: 600;
        }}
        .csa-metric-value {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 26px;
            font-weight: 700;
            color: {TEXT};
            margin-top: 4px;
            line-height: 1.1;
        }}
        .csa-metric-sub {{
            font-size: 11px;
            color: {TEXT_FAINT};
            margin-top: 3px;
            font-family: 'JetBrains Mono', monospace;
        }}

        /* ---------------- Severity badges (terminal log-level style) ---------------- */
        .csa-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 3px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.03em;
            text-transform: uppercase;
            border: 1px solid currentColor;
        }}

        /* ---------------- Buttons ---------------- */
        .stButton>button {{
            background-color: {ACCENT};
            color: #00231F;
            border-radius: 4px;
            border: none;
            font-weight: 600;
            font-size: 13.5px;
            padding: 0.5rem 1.1rem;
            transition: background-color 0.15s ease;
        }}
        .stButton>button:hover {{
            background-color: #5EEAD4;
            color: #00231F;
        }}
        .stButton>button[kind="secondary"] {{
            background-color: transparent;
            border: 1px solid {BORDER};
            color: {TEXT};
        }}
        .stButton>button[kind="secondary"]:hover {{
            border-color: {ACCENT};
            color: {ACCENT};
        }}
        .stDownloadButton>button {{
            background-color: {PANEL_2};
            border: 1px solid {BORDER};
            color: {TEXT};
            border-radius: 4px;
            font-weight: 500;
            font-size: 13px;
        }}
        .stDownloadButton>button:hover {{
            border-color: {ACCENT};
            color: {ACCENT};
        }}

        /* ---------------- Inputs ---------------- */
        .stTextInput input, .stNumberInput input, .stSelectbox [data-baseweb="select"] {{
            background-color: {PANEL_2} !important;
            border: 1px solid {BORDER} !important;
            color: {TEXT} !important;
            border-radius: 4px !important;
        }}
        .stTextInput input:focus, .stNumberInput input:focus {{
            border-color: {ACCENT} !important;
            box-shadow: 0 0 0 1px {ACCENT} !important;
        }}

        /* ---------------- Tabs ---------------- */
        .stTabs [data-baseweb="tab-list"] {{
            gap: 4px;
            border-bottom: 1px solid {BORDER};
        }}
        .stTabs [data-baseweb="tab"] {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12.5px;
            color: {TEXT_DIM};
            background-color: transparent;
            border-radius: 0;
            padding: 8px 4px;
        }}
        .stTabs [aria-selected="true"] {{
            color: {ACCENT} !important;
            border-bottom: 2px solid {ACCENT};
        }}

        /* ---------------- Dataframes / tables ---------------- */
        div[data-testid="stDataFrame"] {{
            border-radius: 4px;
            border: 1px solid {BORDER};
            overflow: hidden;
        }}

        /* ---------------- Native st.metric (used in compact list rows) ---------------- */
        div[data-testid="stMetric"] {{
            background-color: transparent;
        }}
        div[data-testid="stMetricValue"] {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 20px;
            color: {TEXT};
        }}
        div[data-testid="stMetricLabel"] {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: {TEXT_DIM};
        }}

        /* ---------------- Misc ---------------- */
        hr {{ border-color: {BORDER}; }}
        .csa-divider {{
            border-top: 1px solid {BORDER};
            margin: 18px 0;
        }}
        .csa-mono-label {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 12px;
            color: {TEXT_DIM};
        }}
        .csa-empty-state {{
            border: 1px dashed {BORDER};
            border-radius: 6px;
            padding: 36px 24px;
            text-align: center;
            color: {TEXT_DIM};
            font-size: 13.5px;
        }}
        .csa-empty-state .csa-empty-icon {{
            font-family: 'JetBrains Mono', monospace;
            font-size: 24px;
            color: {TEXT_FAINT};
            margin-bottom: 8px;
        }}

        section[data-testid="stSidebar"] div[role="radiogroup"] label {{
            font-size: 13.5px;
            padding: 6px 8px;
            border-radius: 4px;
        }}

        #MainMenu {{visibility: hidden;}}
        footer {{visibility: hidden;}}
    </style>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

def status_bar(username: str, role: str, scan_loaded: bool, db_online: bool = True):
    """Persistent console-style status strip. The signature visual element."""
    db_color = ACCENT if db_online else SEVERITY_COLORS["Critical"]
    scan_color = ACCENT if scan_loaded else TEXT_FAINT
    scan_text = "SCAN LOADED" if scan_loaded else "NO ACTIVE SCAN"
    st.markdown(f"""
    <div class="csa-statusbar">
        <div style="display:flex;flex-wrap:wrap;">
            <div class="csa-status-item"><span class="csa-dot" style="color:{db_color};"></span>DATABASE: ONLINE</div>
            <div class="csa-status-item"><span class="csa-dot" style="color:{scan_color};"></span>{scan_text}</div>
            <div class="csa-status-item">USER: {username or '—'}</div>
            <div class="csa-status-item">ROLE: {(role or '—').upper()}</div>
        </div>
        <div class="csa-status-item">CLOUDSHIELD AI v1.0</div>
    </div>
    """, unsafe_allow_html=True)


def page_header(title: str, caption: str = "", eyebrow: str = "CLOUDSHIELD AI"):
    st.markdown(f"""
    <div class="csa-page-header">
        <span class="csa-page-eyebrow">{eyebrow}</span>
        <div class="csa-page-title">{title}</div>
        {f'<div class="csa-page-caption">{caption}</div>' if caption else ''}
    </div>
    """, unsafe_allow_html=True)


def severity_badge_html(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, TEXT_DIM)
    bg = SEVERITY_BG.get(severity, PANEL_2)
    return (f'<span class="csa-badge" style="background-color:{bg};color:{color};">'
            f'{severity}</span>')


def metric_card(label: str, value, sub: str = None, color: str = None):
    border_color = color or ACCENT
    color_style = f"color:{color};" if color else ""
    sub_html = f'<div class="csa-metric-sub">{sub}</div>' if sub else ""
    st.markdown(f"""
    <div class="csa-metric" style="border-left-color:{border_color};">
        <div class="csa-metric-label">{label}</div>
        <div class="csa-metric-value" style="{color_style}">{value}</div>
        {sub_html}
    </div>
    """, unsafe_allow_html=True)


def panel_start(title: str = None):
    title_html = f'<div class="csa-panel-title">{title}</div>' if title else ""
    st.markdown(f'<div class="csa-panel">{title_html}', unsafe_allow_html=True)


def panel_end():
    st.markdown("</div>", unsafe_allow_html=True)


def empty_state(icon: str, message: str):
    st.markdown(f"""
    <div class="csa-empty-state">
        <div class="csa-empty-icon">{icon}</div>
        {message}
    </div>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Plotly helpers
# ---------------------------------------------------------------------------

def _hex_to_rgba(hex_color: str, alpha: float) -> str:
    hex_color = hex_color.lstrip("#")
    r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def threat_gauge(score: float, title="THREAT SCORE"):
    """Plotly gauge chart for an overall threat score (0-100)."""
    if score <= 20:
        color = SEVERITY_COLORS["Low"]
    elif score <= 50:
        color = SEVERITY_COLORS["Medium"]
    elif score <= 80:
        color = SEVERITY_COLORS["High"]
    else:
        color = SEVERITY_COLORS["Critical"]

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={"text": title, "font": {"color": TEXT_DIM, "size": 12, "family": "JetBrains Mono"}},
        number={"font": {"color": TEXT, "size": 34, "family": "JetBrains Mono"}, "suffix": ""},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": TEXT_FAINT, "tickfont": {"size": 9, "color": TEXT_FAINT}},
            "bar": {"color": color, "thickness": 0.28},
            "bgcolor": PANEL_2,
            "borderwidth": 1,
            "bordercolor": BORDER,
            "steps": [
                {"range": [0, 20], "color": _hex_to_rgba(SEVERITY_COLORS["Low"], 0.12)},
                {"range": [20, 50], "color": _hex_to_rgba(SEVERITY_COLORS["Medium"], 0.12)},
                {"range": [50, 80], "color": _hex_to_rgba(SEVERITY_COLORS["High"], 0.12)},
                {"range": [80, 100], "color": _hex_to_rgba(SEVERITY_COLORS["Critical"], 0.12)},
            ],
        },
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        height=240,
        margin=dict(l=24, r=24, t=44, b=10),
        font=dict(family="Inter"),
    )
    return fig


def plotly_dark_layout(fig, height=380, title=None):
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=TEXT_DIM, family="Inter", size=12),
        height=height,
        margin=dict(l=10, r=10, t=44 if title else 16, b=10),
        title=dict(text=title, font=dict(color=TEXT, size=13, family="Inter")) if title else None,
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=TEXT_DIM)),
        colorway=[ACCENT, SEVERITY_COLORS["High"], SEVERITY_COLORS["Critical"], SEVERITY_COLORS["Low"]],
    )
    fig.update_xaxes(gridcolor=BORDER, zerolinecolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM))
    fig.update_yaxes(gridcolor=BORDER, zerolinecolor=BORDER, linecolor=BORDER, tickfont=dict(color=TEXT_DIM))
    return fig
