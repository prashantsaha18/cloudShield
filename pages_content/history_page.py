import json
import pandas as pd
import streamlit as st

from database import models as db_models
from authentication import auth
from utils.theme import page_header, empty_state, panel_start, panel_end, TEXT_DIM, SEVERITY_COLORS


def render():
    page_header(
        "Scan History",
        "View previous scans. Reload a past scan to revisit its dashboard, reports, and exports.",
        eyebrow="DATA",
    )

    scans = db_models.get_scans_for_user(auth.current_user_id())

    if not scans:
        empty_state("∅", "You haven't run any scans yet. Go to <b>Log Ingestion</b> to get started.")
        return

    for scan in scans:
        report = json.loads(scan["report_json"]) if scan["report_json"] else {}
        st.markdown(f"""
        <div class="csa-panel" style="margin-bottom:6px; padding-bottom:8px;">
            <span class="mono" style="font-size:13.5px; font-weight:600;">{scan['dataset_name']}</span>
            <span style="color:{TEXT_DIM}; font-size:12px; font-family:'JetBrains Mono',monospace;"> &nbsp;{scan['scan_date']}</span>
        </div>
        """, unsafe_allow_html=True)
        cols = st.columns([1, 1, 1, 1])
        cols[0].metric("Logs", scan["total_logs"])
        cols[1].metric("Threats", scan["threat_count"])
        cols[2].metric("Critical", scan["critical_count"])
        with cols[3]:
            st.write("")
            if st.button("Load Scan", key=f"load_{scan['id']}", use_container_width=True):
                events = db_models.get_events_for_scan(scan["id"])
                if events:
                    df = pd.DataFrame(events)
                    st.session_state["active_results_df"] = df
                    st.session_state["active_metrics"] = report
                    st.session_state["active_scan_id"] = scan["id"]
                    st.session_state["active_dataset_name"] = scan["dataset_name"]
                    st.success(f"Loaded scan #{scan['id']}. Go to **Security Dashboard** to view it.")
                else:
                    st.warning("No row-level event data was stored for this scan (it may predate event logging).")
        st.markdown('<div class="csa-divider"></div>', unsafe_allow_html=True)

    if auth.is_admin():
        st.write("")
        panel_start("ALL USERS' SCANS — ADMIN VIEW")
        all_scans = db_models.get_all_scans()
        if all_scans:
            df = pd.DataFrame(all_scans)[["id", "username", "dataset_name", "scan_date", "total_logs", "threat_count", "critical_count"]]
            st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.caption("No scans found across any user.")
        panel_end()
