import pandas as pd
import plotly.express as px
import streamlit as st

from models.train import train_attack_detection
from utils.theme import plotly_dark_layout, page_header, metric_card, panel_start, panel_end, empty_state, ACCENT


def render_confusion_matrix(cm, model_name):
    labels = ["Normal", "Attack"]
    fig = px.imshow(
        cm, x=labels, y=labels, text_auto=True, color_continuous_scale=[[0, "#11151C"], [1, ACCENT]],
        labels=dict(x="Predicted", y="Actual", color="Count"),
    )
    fig = plotly_dark_layout(fig, title=f"{model_name.upper()} — CONFUSION MATRIX", height=300)
    fig.update_layout(coloraxis_showscale=False)
    st.plotly_chart(fig, use_container_width=True)


def render():
    page_header(
        "Attack Detection",
        "Binary classification (Normal vs Attack) using an ensemble of Random Forest and XGBoost.",
        eyebrow="PIPELINE · STEP 3",
    )

    if "df_clean" not in st.session_state:
        empty_state("∅", "No preprocessed data found. Run <b>Preprocessing</b> first.")
        return

    if st.button("Train Detection Models", type="primary"):
        with st.spinner("Training Random Forest and XGBoost detectors..."):
            result = train_attack_detection(st.session_state["df_clean"])
        st.session_state["detection_result"] = result
        st.success("Detection models trained.")

    result = st.session_state.get("detection_result")
    if not result:
        return

    if result["warning"]:
        st.warning(result["warning"])
        return

    metrics = result["metrics"]
    rf_m, xgb_m = metrics["random_forest"], metrics["xgboost"]

    cols = st.columns(4)
    with cols[0]:
        metric_card("RF Accuracy", f"{rf_m['accuracy']*100:.1f}%")
    with cols[1]:
        metric_card("RF F1 Score", f"{rf_m['f1']:.3f}")
    with cols[2]:
        metric_card("XGB Accuracy", f"{xgb_m['accuracy']*100:.1f}%")
    with cols[3]:
        metric_card("XGB F1 Score", f"{xgb_m['f1']:.3f}")

    st.write("")
    panel_start("MODEL PERFORMANCE COMPARISON")
    comp_df = pd.DataFrame({
        "Metric": ["Accuracy", "Precision", "Recall", "F1 Score"],
        "Random Forest": [rf_m["accuracy"], rf_m["precision"], rf_m["recall"], rf_m["f1"]],
        "XGBoost": [xgb_m["accuracy"], xgb_m["precision"], xgb_m["recall"], xgb_m["f1"]],
    })
    st.dataframe(comp_df, use_container_width=True, hide_index=True)
    panel_end()

    col1, col2 = st.columns(2)
    with col1:
        render_confusion_matrix(rf_m["confusion_matrix"], "Random Forest")
    with col2:
        render_confusion_matrix(xgb_m["confusion_matrix"], "XGBoost")

    n_attacks = int(result["ensemble_pred"].sum())
    st.info(f"Ensemble model flagged **{n_attacks:,}** of **{len(result['ensemble_pred']):,}** "
            f"rows as attack traffic. Continue to **Attack Classification**.")
