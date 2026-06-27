import streamlit as st

from exports.export import to_csv_bytes, to_excel_bytes, to_json_bytes, build_executive_summary_pdf
from authentication import auth
from utils.theme import page_header, empty_state, panel_start, panel_end


def render():
    page_header(
        "Export Center",
        "Export your scan results as CSV, Excel, JSON, or a one-page executive PDF summary.",
        eyebrow="DATA",
    )

    if "active_results_df" not in st.session_state or st.session_state["active_results_df"] is None:
        empty_state("∅", "No scan results loaded. Run <b>Threat Scoring</b> first, or load a scan from <b>Scan History</b>.")
        return

    df = st.session_state["active_results_df"]
    metrics = st.session_state["active_metrics"]
    scan_id = st.session_state.get("active_scan_id") or 0
    dataset_name = st.session_state.get("active_dataset_name", "dataset.csv")

    st.markdown(
        f'<span class="csa-mono-label">EXPORTING SCAN #{scan_id} · {len(df):,} ROWS</span>',
        unsafe_allow_html=True,
    )
    st.write("")

    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.download_button(
            "CSV", data=to_csv_bytes(df),
            file_name=f"cloudshield_scan{scan_id}_results.csv", mime="text/csv",
            use_container_width=True,
        )
    with col2:
        st.download_button(
            "Excel", data=to_excel_bytes(df),
            file_name=f"cloudshield_scan{scan_id}_results.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )
    with col3:
        st.download_button(
            "JSON", data=to_json_bytes(df),
            file_name=f"cloudshield_scan{scan_id}_results.json", mime="application/json",
            use_container_width=True,
        )
    with col4:
        pdf_bytes = build_executive_summary_pdf(metrics, dataset_name, auth.current_username())
        st.download_button(
            "Exec Summary PDF", data=pdf_bytes,
            file_name=f"cloudshield_scan{scan_id}_executive_summary.pdf", mime="application/pdf",
            use_container_width=True,
        )

    st.write("")
    panel_start("DATA PREVIEW")
    st.dataframe(df.head(50), use_container_width=True)
    panel_end()
