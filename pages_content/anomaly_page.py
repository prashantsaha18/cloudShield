import plotly.express as px
import streamlit as st

from models.train import train_anomaly_detection
from utils.theme import plotly_dark_layout, page_header, metric_card, panel_start, panel_end, empty_state, ACCENT


def render():
    page_header(
        "Anomaly Detection",
        "Isolation Forest flags suspicious traffic and hidden threats independent of labeled attack types.",
        eyebrow="PIPELINE · STEP 5",
    )

    if "df_clean" not in st.session_state:
        empty_state("∅", "No preprocessed data found. Run <b>Preprocessing</b> first.")
        return

    df_clean = st.session_state["df_clean"]

    contamination = st.slider(
        "Expected contamination (proportion of anomalies)", 0.01, 0.30, 0.10, step=0.01,
        help="Roughly how much of the traffic you expect to be anomalous.",
    )

    if st.button("Run Anomaly Detection", type="primary"):
        with st.spinner("Running Isolation Forest..."):
            result = train_anomaly_detection(df_clean, contamination=contamination)
        st.session_state["anomaly_result"] = result
        st.success("Anomaly detection complete.")

    result = st.session_state.get("anomaly_result")
    if not result:
        return

    scores = result["anomaly_scores"]
    n_anomalies = int(result["is_anomaly"].sum())

    col1, col2 = st.columns(2)
    with col1:
        metric_card("Anomalies Flagged", f"{n_anomalies:,}")
    with col2:
        metric_card("Avg Anomaly Score", f"{scores.mean():.1f}", sub="/ 100")

    st.write("")
    fig = px.histogram(scores, nbins=40, color_discrete_sequence=[ACCENT])
    fig = plotly_dark_layout(fig, title="ANOMALY SCORE DISTRIBUTION", height=320)
    fig.update_layout(showlegend=False, xaxis_title="Anomaly Score", yaxis_title="Count")
    st.plotly_chart(fig, use_container_width=True)

    preview = df_clean.copy()
    preview["anomaly_score"] = scores
    preview["is_anomaly"] = result["is_anomaly"]
    top_anomalies = preview[preview["is_anomaly"]].sort_values("anomaly_score", ascending=False).head(20)
    if not top_anomalies.empty:
        panel_start("TOP ANOMALOUS EVENTS")
        st.dataframe(
            top_anomalies[["timestamp", "source_ip", "destination_ip", "protocol",
                           "bytes_sent", "bytes_received", "connection_duration", "anomaly_score"]],
            use_container_width=True, hide_index=True,
        )
        panel_end()

    st.info("Continue to **Threat Scoring**.")
