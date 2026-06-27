"""
CloudShield AI - Security Dashboard & Visualization Center
Combines Module 8 (Security Dashboard) and Module 11 (Visualization Center).
"""

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from utils.theme import (
    plotly_dark_layout, SEVERITY_COLORS, ACCENT, TEXT_DIM, PANEL_2,
    metric_card, panel_start, panel_end, empty_state,
)

NORMAL_COLOR = SEVERITY_COLORS["Low"]
ATTACK_COLOR = SEVERITY_COLORS["Critical"]


def render_kpi_row(metrics: dict):
    cols = st.columns(5)
    with cols[0]:
        metric_card("Total Logs", f"{metrics.get('total_logs', 0):,}")
    with cols[1]:
        metric_card("Normal Events", f"{metrics.get('normal_count', 0):,}", color=NORMAL_COLOR)
    with cols[2]:
        metric_card("Detected Attacks", f"{metrics.get('attack_count', 0):,}", color=SEVERITY_COLORS["High"])
    with cols[3]:
        metric_card("Critical Threats", f"{metrics.get('critical_count', 0):,}", color=SEVERITY_COLORS["Critical"])
    with cols[4]:
        attack_rate = (metrics.get("attack_count", 0) / metrics.get("total_logs", 1) * 100) if metrics.get("total_logs") else 0
        metric_card("Attack Rate", f"{attack_rate:.1f}%")


def render_attack_timeline(df: pd.DataFrame):
    df = df.copy()
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp_dt"])
    if df.empty:
        empty_state("∅", "No valid timestamps available for timeline view.")
        return

    df["hour_bucket"] = df["timestamp_dt"].dt.floor("h")
    timeline = df.groupby(["hour_bucket", "predicted_label"]).size().reset_index(name="count")

    fig = px.area(
        timeline, x="hour_bucket", y="count", color="predicted_label",
        color_discrete_map={"Normal": NORMAL_COLOR, "Attack": ATTACK_COLOR},
    )
    fig = plotly_dark_layout(fig, title="ATTACK TIMELINE (HOURLY)")
    st.plotly_chart(fig, use_container_width=True)


def render_threat_distribution(df: pd.DataFrame):
    counts = df["severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"]).fillna(0)
    fig = go.Figure(data=[go.Pie(
        labels=counts.index, values=counts.values, hole=0.6,
        marker=dict(colors=[SEVERITY_COLORS[s] for s in counts.index], line=dict(color="#0A0E14", width=2)),
        textinfo="label+percent",
        textfont=dict(size=11),
    )])
    fig = plotly_dark_layout(fig, title="THREAT SEVERITY DISTRIBUTION", height=320)
    st.plotly_chart(fig, use_container_width=True)


def render_attack_type_breakdown(df: pd.DataFrame):
    attacks = df[df["predicted_label"] == "Attack"]
    if attacks.empty:
        empty_state("∅", "No attacks detected in this scan.")
        return
    counts = attacks["attack_type_predicted"].value_counts().reset_index()
    counts.columns = ["attack_type", "count"]
    fig = px.bar(
        counts, x="count", y="attack_type", orientation="h",
        color_discrete_sequence=[SEVERITY_COLORS["High"]],
    )
    fig = plotly_dark_layout(fig, title="MOST COMMON ATTACKS", height=360)
    fig.update_layout(showlegend=False)
    fig.update_yaxes(autorange="reversed")
    st.plotly_chart(fig, use_container_width=True)


def render_top_ips(df: pd.DataFrame):
    attacks = df[df["predicted_label"] == "Attack"]
    col1, col2 = st.columns(2)

    with col1:
        if attacks.empty:
            empty_state("∅", "No attack source IPs to display.")
        else:
            top_src = attacks["source_ip"].value_counts().head(10).reset_index()
            top_src.columns = ["source_ip", "count"]
            fig = px.bar(top_src, x="count", y="source_ip", orientation="h", color_discrete_sequence=[ACCENT])
            fig = plotly_dark_layout(fig, title="TOP SOURCE IPs (ATTACKS)", height=340)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        if attacks.empty:
            empty_state("∅", "No destination IPs to display.")
        else:
            top_dst = attacks["destination_ip"].value_counts().head(10).reset_index()
            top_dst.columns = ["destination_ip", "count"]
            fig = px.bar(top_dst, x="count", y="destination_ip", orientation="h",
                        color_discrete_sequence=[SEVERITY_COLORS["High"]])
            fig = plotly_dark_layout(fig, title="TOP DESTINATION IPs (TARGETED)", height=340)
            fig.update_yaxes(autorange="reversed")
            st.plotly_chart(fig, use_container_width=True)


def render_attack_heatmap(df: pd.DataFrame):
    df = df.copy()
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp_dt"])
    attacks = df[df["predicted_label"] == "Attack"]
    if attacks.empty:
        empty_state("∅", "No attack data available for heatmap.")
        return

    attacks = attacks.copy()
    attacks["hour"] = attacks["timestamp_dt"].dt.hour
    attacks["day"] = attacks["timestamp_dt"].dt.day_name()
    pivot = attacks.pivot_table(index="day", columns="hour", values="threat_score", aggfunc="count", fill_value=0)

    day_order = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    pivot = pivot.reindex([d for d in day_order if d in pivot.index])

    fig = px.imshow(
        pivot, color_continuous_scale=[[0, PANEL_2], [1, SEVERITY_COLORS["Critical"]]], aspect="auto",
        labels=dict(x="Hour of Day", y="Day", color="Attacks"),
    )
    fig = plotly_dark_layout(fig, title="ATTACK HEATMAP (DAY × HOUR)", height=300)
    st.plotly_chart(fig, use_container_width=True)


def render_network_traffic_analysis(df: pd.DataFrame):
    fig = px.scatter(
        df.sample(min(2000, len(df))), x="bytes_sent", y="bytes_received",
        color="predicted_label", size="connection_duration",
        color_discrete_map={"Normal": NORMAL_COLOR, "Attack": ATTACK_COLOR},
        opacity=0.6, hover_data=["source_ip", "destination_ip", "attack_type_predicted"],
    )
    fig = plotly_dark_layout(fig, title="NETWORK TRAFFIC ANALYSIS (SENT VS RECEIVED BYTES)", height=400)
    st.plotly_chart(fig, use_container_width=True)


def render_threat_leaderboard(df: pd.DataFrame, top_n=10):
    """Bonus feature: leaderboard of riskiest source IPs."""
    attacks = df[df["predicted_label"] == "Attack"]
    if attacks.empty:
        empty_state("∅", "No attackers to rank.")
        return
    leaderboard = (
        attacks.groupby("source_ip")
        .agg(events=("source_ip", "count"), avg_threat_score=("threat_score", "mean"),
             max_threat_score=("threat_score", "max"))
        .sort_values("avg_threat_score", ascending=False)
        .head(top_n)
        .reset_index()
    )
    leaderboard["avg_threat_score"] = leaderboard["avg_threat_score"].round(1)
    leaderboard["max_threat_score"] = leaderboard["max_threat_score"].round(1)
    leaderboard.index = leaderboard.index + 1
    leaderboard.index.name = "Rank"
    st.dataframe(leaderboard, use_container_width=True)


def render_attack_forecast(df: pd.DataFrame):
    """
    Bonus feature: simple short-horizon attack forecast using linear
    extrapolation over hourly attack counts (kept deliberately simple
    and clearly labeled as a heuristic, not a production forecasting model).
    """
    df = df.copy()
    df["timestamp_dt"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp_dt"])
    attacks = df[df["predicted_label"] == "Attack"]
    if len(attacks) < 5:
        empty_state("∅", "Not enough attack data to generate a forecast.")
        return

    hourly = attacks.set_index("timestamp_dt").resample("h").size()
    if len(hourly) < 3:
        empty_state("∅", "Not enough time spread in the data to forecast.")
        return

    x = np.arange(len(hourly))
    coeffs = np.polyfit(x, hourly.values, 1)
    future_x = np.arange(len(hourly), len(hourly) + 6)
    future_y = np.clip(np.polyval(coeffs, future_x), 0, None)

    future_index = pd.date_range(hourly.index[-1] + pd.Timedelta(hours=1), periods=6, freq="h")

    fig = go.Figure()
    fig.add_trace(go.Scatter(x=hourly.index, y=hourly.values, mode="lines+markers", name="Observed",
                              line=dict(color=ACCENT)))
    fig.add_trace(go.Scatter(x=future_index, y=future_y, mode="lines+markers", name="Forecast (trend)",
                              line=dict(color=SEVERITY_COLORS["High"], dash="dash")))
    fig = plotly_dark_layout(fig, title="ATTACK FORECAST — NEXT 6 HOURS (LINEAR TREND HEURISTIC)", height=340)
    st.plotly_chart(fig, use_container_width=True)
    st.caption("This is a simple linear-trend projection for illustrative purposes, not a calibrated forecasting model.")
