import streamlit as st
from preprocessing.preprocess import preprocess
from utils.theme import page_header, metric_card, panel_start, panel_end, empty_state


def render():
    page_header(
        "Preprocessing",
        "Missing-value handling, label encoding, feature scaling, outlier detection, deduplication.",
        eyebrow="PIPELINE · STEP 2",
    )

    if "raw_df" not in st.session_state:
        empty_state("∅", "No dataset staged yet. Go to <b>Log Ingestion</b> first.")
        return

    raw_df = st.session_state["raw_df"]
    st.markdown(
        f'<span class="csa-mono-label">STAGED:</span> '
        f'<span class="mono">{st.session_state.get("active_dataset_name")}</span> '
        f'<span class="csa-mono-label">— {len(raw_df):,} rows</span>',
        unsafe_allow_html=True,
    )
    st.write("")

    if st.button("Run Preprocessing Pipeline", type="primary"):
        with st.spinner("Cleaning and transforming data..."):
            df_clean, encoders, scaler, report = preprocess(raw_df)
        st.session_state["df_clean"] = df_clean
        st.session_state["quality_report"] = report
        st.session_state.pop("pipeline_result", None)
        st.success("Preprocessing complete.")

    if "quality_report" in st.session_state:
        report = st.session_state["quality_report"]
        st.write("")
        cols = st.columns(4)
        with cols[0]:
            metric_card("Original Rows", f"{report['original_rows']:,}")
        with cols[1]:
            metric_card("Cleaned Rows", f"{report['cleaned_rows']:,}")
        with cols[2]:
            metric_card("Duplicates Removed", f"{report['duplicates_removed']:,}")
        with cols[3]:
            metric_card("Outliers Flagged", f"{report['outliers_flagged']:,}")

        st.write("")
        panel_start("CLEANED DATA PREVIEW")
        st.dataframe(st.session_state["df_clean"].head(20), use_container_width=True)
        panel_end()
        st.info("Preprocessing complete. Continue to **Attack Detection**.")
