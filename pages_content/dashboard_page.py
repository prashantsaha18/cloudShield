import streamlit as st

from dashboard import dashboard as dash
from utils.theme import threat_gauge, page_header, empty_state


def render():
    page_header("Security Dashboard", "Live KPIs, severity breakdown, attack timeline, and top offenders.", eyebrow="ANALYSIS")

    if "active_results_df" not in st.session_state or st.session_state["active_results_df"] is None:
        empty_state("∅", "No scan results loaded. Run <b>Threat Scoring</b> first, or load a scan from <b>Scan History</b>.")
        return

    df = st.session_state["active_results_df"]
    metrics = st.session_state["active_metrics"]

    dash.render_kpi_row(metrics)
    st.write("")

    col1, col2 = st.columns([1, 2])
    with col1:
        overall_score = round(df["threat_score"].mean(), 1)
        st.plotly_chart(threat_gauge(overall_score), use_container_width=True)
    with col2:
        dash.render_threat_distribution(df)

    dash.render_attack_timeline(df)
    dash.render_attack_type_breakdown(df)
    dash.render_top_ips(df)
