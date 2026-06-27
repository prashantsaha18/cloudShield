import pandas as pd
import streamlit as st

from database import models as db_models
from authentication import auth
from utils.theme import page_header, metric_card


def render():
    page_header("Admin Panel", "Platform-wide stats, user management, scan oversight, and audit log.", eyebrow="ADMIN")

    if not auth.is_admin():
        st.error("You do not have permission to view this page.")
        return

    tab_overview, tab_users, tab_scans, tab_audit = st.tabs(
        ["OVERVIEW", "USERS", "SCANS", "AUDIT LOG"]
    )

    with tab_overview:
        c1, c2, c3 = st.columns(3)
        with c1:
            metric_card("Total Users", db_models.count_users())
        with c2:
            metric_card("Total Scans", db_models.count_scans())
        with c3:
            metric_card("Threats Detected (all scans)", f"{db_models.sum_threats():,}")

    with tab_users:
        users = db_models.list_all_users()
        if users:
            st.dataframe(pd.DataFrame(users), use_container_width=True, hide_index=True)
        else:
            st.caption("No users found.")

    with tab_scans:
        scans = db_models.get_all_scans()
        if scans:
            df = pd.DataFrame(scans)[["id", "username", "dataset_name", "scan_date",
                                       "total_logs", "threat_count", "critical_count"]]
            st.dataframe(df, use_container_width=True, hide_index=True)

            st.write("")
            st.markdown("##### Delete a Scan")
            scan_id_to_delete = st.number_input("Scan ID to delete", min_value=0, step=1)
            if st.button("Delete Scan", type="secondary"):
                if scan_id_to_delete > 0:
                    db_models.delete_scan(int(scan_id_to_delete))
                    db_models.log_action(auth.current_user_id(), "admin_delete_scan",
                                          f"Deleted scan #{int(scan_id_to_delete)}")
                    st.success(f"Scan #{int(scan_id_to_delete)} deleted.")
                    st.rerun()
        else:
            st.caption("No scans found.")

    with tab_audit:
        log = db_models.get_recent_audit_log(200)
        if log:
            st.dataframe(pd.DataFrame(log), use_container_width=True, hide_index=True)
        else:
            st.caption("No audit log entries yet.")
