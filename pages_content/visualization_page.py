import streamlit as st

from dashboard import dashboard as dash
from utils.theme import page_header, empty_state


def render():
    page_header(
        "Visualization Center",
        "Deeper analytical views: heatmaps, network traffic patterns, leaderboards, and forecasting.",
        eyebrow="ANALYSIS",
    )

    if "active_results_df" not in st.session_state or st.session_state["active_results_df"] is None:
        empty_state("∅", "No scan results loaded. Run <b>Threat Scoring</b> first, or load a scan from <b>Scan History</b>.")
        return

    df = st.session_state["active_results_df"]

    tabs = st.tabs(["ATTACK HEATMAP", "NETWORK TRAFFIC", "THREAT LEADERBOARD", "ATTACK FORECAST"])

    with tabs[0]:
        dash.render_attack_heatmap(df)

    with tabs[1]:
        dash.render_network_traffic_analysis(df)

    with tabs[2]:
        st.caption("Bonus feature: ranks the riskiest source IPs by average threat score.")
        dash.render_threat_leaderboard(df)

    with tabs[3]:
        dash.render_attack_forecast(df)
