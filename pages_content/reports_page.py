import streamlit as st

from reports.report_generator import generate_incident_records, build_incident_pdf
from database import models as db_models
from authentication import auth
from utils.theme import severity_badge_html, page_header, empty_state, TEXT_DIM


def render():
    page_header(
        "Incident Reports",
        "Generates professional SOC-style incident reports for High/Critical severity findings.",
        eyebrow="ANALYSIS",
    )

    if "active_results_df" not in st.session_state or st.session_state["active_results_df"] is None:
        empty_state("∅", "No scan results loaded. Run <b>Threat Scoring</b> first, or load a scan from <b>Scan History</b>.")
        return

    df = st.session_state["active_results_df"]
    metrics = st.session_state["active_metrics"]
    scan_id = st.session_state.get("active_scan_id") or 0

    min_severity = st.selectbox("Minimum severity to include", ["Critical", "High", "Medium", "Low"], index=1)

    if st.button("Generate Incident Records", type="primary"):
        incidents = generate_incident_records(df, scan_id=scan_id, min_severity=min_severity)
        st.session_state["incidents"] = incidents

        for inc in incidents:
            try:
                db_models.create_incident_report(
                    scan_id=scan_id,
                    incident_id=inc["incident_id"],
                    threat_type=inc["threat_type"],
                    severity=inc["severity"],
                    affected_assets=", ".join(inc["affected_assets"]),
                    recommended_actions=inc["recommended_actions"],
                )
            except Exception:
                pass  # scan_id may be 0/transient in edge cases; don't block report viewing

        st.success(f"Generated {len(incidents)} incident record(s).")

    incidents = st.session_state.get("incidents")
    if incidents is None:
        return

    if not incidents:
        st.info(f"No incidents at or above **{min_severity}** severity were found in this scan.")
    else:
        for inc in incidents:
            badge = severity_badge_html(inc["severity"])
            st.markdown(f"""
            <div class="csa-panel">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span class="mono" style="font-size:14px; font-weight:700;">{inc['incident_id']}</span>
                    {badge}
                </div>
                <p style="margin-top:10px; font-size:13.5px; color:{TEXT_DIM};">
                    <b style="color:#E6E9EF;">Threat Type:</b> {inc['threat_type']} &nbsp;·&nbsp;
                    <b style="color:#E6E9EF;">Events:</b> {inc['event_count']} &nbsp;·&nbsp;
                    <b style="color:#E6E9EF;">Avg Score:</b> <span class="mono">{inc['avg_threat_score']}/100</span>
                </p>
                <p style="font-size:13px; color:{TEXT_DIM};">
                    <b style="color:#E6E9EF;">Affected:</b> <span class="mono">{', '.join(inc['affected_assets'])}</span>
                </p>
                <p style="font-size:13px; color:{TEXT_DIM};">
                    <b style="color:#E6E9EF;">Source IP(s):</b> <span class="mono">{', '.join(inc['source_ips'])}</span>
                </p>
            </div>
            """, unsafe_allow_html=True)
            with st.expander("Recommended Actions"):
                for i, action in enumerate(inc["recommended_actions"], 1):
                    st.write(f"{i}. {action}")

    st.write("")
    st.markdown('<div class="csa-divider"></div>', unsafe_allow_html=True)
    st.markdown("##### Download Full Report")
    pdf_bytes = build_incident_pdf(
        incidents or [],
        dataset_name=st.session_state.get("active_dataset_name", "dataset.csv"),
        analyst_name=auth.current_username(),
        summary_metrics=metrics,
    )
    st.download_button(
        "Download Incident Report (PDF)",
        data=pdf_bytes,
        file_name=f"cloudshield_incident_report_scan{scan_id}.pdf",
        mime="application/pdf",
        type="primary",
    )
