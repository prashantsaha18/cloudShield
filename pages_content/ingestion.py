import pandas as pd
import streamlit as st

from preprocessing.preprocess import validate_csv, REQUIRED_COLUMNS, MAX_ROWS
from preprocessing.synthetic_data import generate_synthetic_logs, get_sample_csv_bytes
from utils.theme import page_header


def render():
    page_header("Log Ingestion", "Upload a CSV of security or network logs, or generate a synthetic demo dataset.", eyebrow="PIPELINE · STEP 1")

    with st.expander("Expected CSV schema", expanded=False):
        st.code(", ".join(REQUIRED_COLUMNS + ["attack_type (optional)"]))
        st.download_button(
            "Download sample CSV",
            data=get_sample_csv_bytes(n_rows=500),
            file_name="cloudshield_sample_logs.csv",
            mime="text/csv",
        )

    tab_upload, tab_generate = st.tabs(["Upload CSV", "Generate Synthetic Dataset"])

    with tab_upload:
        uploaded = st.file_uploader("Upload log file (.csv)", type=["csv"])
        if uploaded is not None:
            try:
                df = pd.read_csv(uploaded)
            except Exception as e:
                st.error(f"Could not read CSV: {e}")
                return

            if len(df) > MAX_ROWS:
                st.warning(
                    f"This file has {len(df):,} rows. To keep scoring fast, only the first "
                    f"{MAX_ROWS:,} rows will be used. Split larger files into multiple scans "
                    f"if you need full coverage."
                )
                df = df.head(MAX_ROWS).copy()

            is_valid, issues = validate_csv(df)
            if not is_valid:
                st.error("This file cannot be used:")
                for issue in issues:
                    st.write(f"- {issue}")
            else:
                if issues:
                    st.warning("File is usable, but with some data quality notes:")
                    for issue in issues:
                        st.write(f"- {issue}")
                st.success(f"Loaded {len(df):,} rows from **{uploaded.name}**")
                st.dataframe(df.head(20), use_container_width=True)

                if st.button("Use this dataset", type="primary"):
                    st.session_state["raw_df"] = df
                    st.session_state["active_dataset_name"] = uploaded.name
                    # Clear any downstream cached results from a previous dataset
                    for k in ["df_clean", "pipeline_result", "active_scan_id"]:
                        st.session_state.pop(k, None)
                    st.success("Dataset staged. Go to **Preprocessing** next.")

    with tab_generate:
        st.write("Generate a realistic synthetic dataset modeled on common network log patterns "
                 "(DDoS, DoS, Brute Force, Port Scan, SQL Injection, Botnet, Malware, Phishing, etc.)")
        col1, col2 = st.columns(2)
        with col1:
            n_rows = st.slider("Number of log entries", 200, MAX_ROWS, 2000, step=200)
        with col2:
            attack_ratio = st.slider("Approx. attack ratio", 0.05, 0.5, 0.22, step=0.01)

        if n_rows > 5000:
            st.caption(f"Datasets over 5,000 rows take longer to score — expect roughly "
                       f"{n_rows / 5000 * 2:.0f}-{n_rows / 5000 * 3:.0f}s for the full pipeline.")

        if st.button("Generate Dataset", type="primary"):
            df = generate_synthetic_logs(n_rows=n_rows, attack_ratio=attack_ratio)
            st.session_state["raw_df"] = df
            st.session_state["active_dataset_name"] = f"synthetic_{n_rows}rows.csv"
            for k in ["df_clean", "pipeline_result", "active_scan_id"]:
                st.session_state.pop(k, None)
            st.success(f"Generated {len(df):,} synthetic log entries.")
            st.dataframe(df.head(20), use_container_width=True)
            st.info("Dataset staged. Go to **Preprocessing** next.")

    if "raw_df" in st.session_state:
        st.divider()
        st.caption(f"Currently staged dataset: **{st.session_state.get('active_dataset_name')}** "
                   f"({len(st.session_state['raw_df']):,} rows)")
