import streamlit as st
from database import models
from authentication import auth
from utils.theme import page_header, metric_card, panel_start, panel_end, SEVERITY_COLORS, TEXT_FAINT, ACCENT


PIPELINE_STAGES = [
    ("Log Ingestion", "raw_df"),
    ("Preprocessing", "df_clean"),
    ("Attack Detection", "detection_result"),
    ("Attack Classification", "classification_result"),
    ("Anomaly Detection", "anomaly_result"),
    ("Threat Scoring", "pipeline_result"),
]


def render_pipeline_status():
    panel_start("CURRENT SESSION PIPELINE")
    cols = st.columns(len(PIPELINE_STAGES))
    for i, (label, session_key) in enumerate(PIPELINE_STAGES):
        done = session_key in st.session_state and st.session_state[session_key] is not None
        color = ACCENT if done else TEXT_FAINT
        glyph = "●" if done else "○"
        with cols[i]:
            st.markdown(f"""
            <div style="text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace; font-size:18px; color:{color};">{glyph}</div>
                <div style="font-size:10.5px; color:{color}; margin-top:2px; line-height:1.3;">{label}</div>
            </div>
            """, unsafe_allow_html=True)
    panel_end()


def render():
    page_header(
        "Home",
        "Session overview and quick-start guide for the threat hunting pipeline.",
        eyebrow="OVERVIEW",
    )

    user_scans = models.get_scans_for_user(auth.current_user_id())
    total_threats = sum(s["threat_count"] for s in user_scans) if user_scans else 0
    total_critical = sum(s["critical_count"] for s in user_scans) if user_scans else 0

    cols = st.columns(4)
    with cols[0]:
        metric_card("Scans Run", len(user_scans))
    with cols[1]:
        metric_card("Threats Found", f"{total_threats:,}", color=SEVERITY_COLORS["High"])
    with cols[2]:
        metric_card("Critical (All Time)", f"{total_critical:,}", color=SEVERITY_COLORS["Critical"])
    with cols[3]:
        active = "LOADED" if st.session_state.get("active_scan_id") else "NONE"
        metric_card("Active Scan", active)

    st.write("")
    render_pipeline_status()

    st.write("")
    panel_start("QUICK START")
    st.markdown("""
    **1.** Go to **Log Ingestion** — upload a CSV of network/security logs, or generate a synthetic demo dataset.<br>
    **2.** Run **Preprocessing → Attack Detection → Attack Classification → Anomaly Detection → Threat Scoring** in order.<br>
    **3.** Review findings on **Security Dashboard** and **Visualization Center**.<br>
    **4.** Generate a SOC-style **Incident Report** (PDF) for High/Critical findings.<br>
    **5.** Export results from **Export Center**, or revisit past work in **Scan History**.
    """, unsafe_allow_html=True)
    panel_end()

    if user_scans:
        st.write("")
        panel_start("RECENT SCANS")
        for s in user_scans[:5]:
            st.markdown(f"""
            <div style="display:flex; justify-content:space-between; align-items:center;
                        padding:8px 0; border-bottom:1px solid #232A35; font-size:13px;">
                <span class="mono">{s['dataset_name']}</span>
                <span style="color:#7C8595; font-family:'JetBrains Mono',monospace; font-size:12px;">
                    {s['scan_date']} &nbsp;·&nbsp; {s['total_logs']} logs &nbsp;·&nbsp;
                    <span style="color:{SEVERITY_COLORS['High']};">{s['threat_count']} threats</span> &nbsp;·&nbsp;
                    <span style="color:{SEVERITY_COLORS['Critical']};">{s['critical_count']} critical</span>
                </span>
            </div>
            """, unsafe_allow_html=True)
        panel_end()
