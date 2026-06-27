import numpy as np
import pandas as pd
import plotly.express as px
import streamlit as st

from models.train import train_attack_classification
from utils.theme import plotly_dark_layout, page_header, metric_card, panel_start, panel_end, empty_state, SEVERITY_COLORS


def render():
    page_header(
        "Attack Classification",
        "Classifies detected attacks into specific threat categories with probability scores.",
        eyebrow="PIPELINE · STEP 4",
    )

    if "df_clean" not in st.session_state:
        empty_state("∅", "No preprocessed data found. Run <b>Preprocessing</b> first.")
        return
    if "detection_result" not in st.session_state or st.session_state["detection_result"].get("rf_model") is None:
        empty_state("∅", "Run <b>Attack Detection</b> first so we know which rows to classify.")
        return

    df_clean = st.session_state["df_clean"]

    if st.button("Train Classification Model", type="primary"):
        ground_truth_mask = (df_clean["attack_type"] != "Normal").values
        with st.spinner("Training multiclass attack classifier..."):
            result = train_attack_classification(df_clean, ground_truth_mask)
        st.session_state["classification_result"] = result
        st.success("Classification model trained.")

    result = st.session_state.get("classification_result")
    if not result:
        return

    if result["warning"]:
        st.warning(result["warning"])
        if result["model"] is None:
            return

    metric_card("Classification Accuracy", f"{result['metrics']['accuracy'] * 100:.1f}%",
                sub="held-out attack samples")
    st.write("")

    detection_result = st.session_state["detection_result"]
    detected_idx = np.where(detection_result["ensemble_pred"] == 1)[0]

    if len(detected_idx) == 0:
        st.info("No rows were flagged as attacks by the detection stage.")
        return

    all_proba = result["all_proba"]
    class_names = result["class_names"]

    rows = []
    for i in detected_idx[:200]:  # cap table size for responsiveness
        proba_row = all_proba[i]
        best = int(np.argmax(proba_row))
        rows.append({
            "source_ip": df_clean["source_ip"].iloc[i],
            "destination_ip": df_clean["destination_ip"].iloc[i],
            "predicted_attack_type": class_names[best],
            "confidence": round(float(proba_row[best]), 3),
        })
    preview_df = pd.DataFrame(rows)

    panel_start(f"CLASSIFIED ATTACKS — showing up to 200 of {len(detected_idx):,}")
    st.dataframe(preview_df, use_container_width=True, hide_index=True)
    panel_end()

    type_counts = preview_df["predicted_attack_type"].value_counts().reset_index()
    type_counts.columns = ["attack_type", "count"]
    fig = px.bar(type_counts, x="attack_type", y="count", color_discrete_sequence=[SEVERITY_COLORS["High"]])
    fig = plotly_dark_layout(fig, title="PREDICTED ATTACK TYPE DISTRIBUTION (SAMPLE)", height=340)
    fig.update_layout(showlegend=False)
    st.plotly_chart(fig, use_container_width=True)

    st.info("Continue to **Anomaly Detection**.")
