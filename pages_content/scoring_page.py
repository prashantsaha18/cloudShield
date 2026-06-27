import streamlit as st

from models.predict import run_full_pipeline
from database import models as db_models
from authentication import auth
from utils.theme import threat_gauge, page_header, metric_card, panel_start, panel_end, empty_state, severity_badge_html


def render():
    page_header(
        "Threat Scoring",
        "Combines attack probability, anomaly score, frequency, and severity weight into a unified threat score.",
        eyebrow="PIPELINE · STEP 6",
    )

    if "df_clean" not in st.session_state:
        empty_state("∅", "No preprocessed data found. Run <b>Preprocessing</b> first.")
        return

    st.markdown(
        '<span class="csa-mono-label">This step runs the complete pipeline '
        '(detection → classification → anomaly → scoring) and saves the results '
        'as a scan you can revisit later.</span>',
        unsafe_allow_html=True,
    )
    st.write("")

    if st.button("Run Full Threat Scoring Pipeline", type="primary"):
        with st.spinner("Running full ML pipeline — training all models end-to-end..."):
            result = run_full_pipeline(st.session_state["df_clean"])
        st.session_state["pipeline_result"] = result

        metrics = result["metrics"]
        scan_id = db_models.create_scan(
            user_id=auth.current_user_id(),
            dataset_name=st.session_state.get("active_dataset_name", "unnamed_dataset.csv"),
            total_logs=metrics["total_logs"],
            threat_count=metrics["attack_count"],
            critical_count=metrics["critical_count"],
            report_obj=metrics,
        )
        st.session_state["active_scan_id"] = scan_id

        try:
            db_models.bulk_insert_events(scan_id, result["results_df"].head(5000))
        except Exception as e:
            st.warning(f"Scan results computed, but could not persist row-level history: {e}")

        db_models.log_action(auth.current_user_id(), "run_scan",
                              f"Scan #{scan_id} on {st.session_state.get('active_dataset_name')}")

        st.session_state["active_results_df"] = result["results_df"]
        st.session_state["active_metrics"] = metrics
        st.success(f"Pipeline complete. Scan #{scan_id} saved.")

    result = st.session_state.get("pipeline_result")
    if not result:
        return

    for w in result["warnings"]:
        st.warning(w)

    metrics = result["metrics"]
    overall_score = round(result["results_df"]["threat_score"].mean(), 1)

    col1, col2 = st.columns([1, 2])
    with col1:
        st.plotly_chart(threat_gauge(overall_score, title="AVERAGE THREAT SCORE"), use_container_width=True)
    with col2:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("Total Logs", f"{metrics['total_logs']:,}")
        with c2:
            metric_card("Attacks", f"{metrics['attack_count']:,}")
        with c3:
            from utils.theme import SEVERITY_COLORS
            metric_card("Critical", f"{metrics['critical_count']:,}", color=SEVERITY_COLORS["Critical"])
        with c4:
            metric_card("High", f"{metrics['high_count']:,}", color=SEVERITY_COLORS["High"])

    st.write("")
    panel_start("TOP SCORED EVENTS")
    display_cols = [
        "timestamp", "source_ip", "destination_ip", "attack_type_predicted",
        "attack_probability", "anomaly_score", "frequency_score", "severity_weight",
        "threat_score", "severity",
    ]
    top_events = result["results_df"][display_cols].sort_values("threat_score", ascending=False).head(50)
    st.dataframe(top_events, use_container_width=True, hide_index=True)
    panel_end()

    st.info("View full visualizations on **Security Dashboard**, or generate a report on **Incident Reports**.")
