"""
CloudShield AI - Threat Scoring Engine
Combines attack probability, anomaly score, frequency score, and a
severity weight per attack type into a single 0-100 threat score, and
buckets it into Low / Medium / High / Critical.
"""

import numpy as np
import pandas as pd

# Relative severity weight per attack type (0-1), used as one component
# of the composite threat score. Higher = inherently more dangerous.
SEVERITY_WEIGHTS = {
    "DDoS": 0.95,
    "Botnet": 0.90,
    "Malware": 0.92,
    "SQL Injection": 0.88,
    "DoS": 0.80,
    "Brute Force": 0.65,
    "Phishing": 0.70,
    "Port Scan": 0.40,
    "Unknown Threat": 0.55,
    "Normal": 0.0,
}


def severity_bucket(score: float) -> str:
    if score <= 20:
        return "Low"
    elif score <= 50:
        return "Medium"
    elif score <= 80:
        return "High"
    else:
        return "Critical"


def compute_frequency_scores(df: pd.DataFrame) -> np.ndarray:
    """
    Frequency score (0-100) based on how often each source_ip appears
    relative to the busiest source in the dataset. Repeated offenders
    score higher.
    """
    counts = df["source_ip"].value_counts()
    max_count = counts.max() if len(counts) else 1
    freq_map = (counts / max_count * 100).to_dict()
    return df["source_ip"].map(freq_map).fillna(0).values


def compute_threat_scores(
    df: pd.DataFrame,
    attack_probability: np.ndarray,
    anomaly_score: np.ndarray,
    predicted_attack_type: list,
) -> pd.DataFrame:
    """
    Threat Score = weighted blend of:
      - attack probability (0-100)
      - anomaly score (0-100)
      - frequency score (0-100)
      - severity weight (0-1, scaled to 0-100)

    Weighting: 35% attack probability, 25% anomaly, 20% frequency, 20% severity.
    Returns df with added columns: frequency_score, severity_weight, threat_score, severity.
    """
    df = df.copy()

    freq_score = compute_frequency_scores(df)
    severity_w = np.array([SEVERITY_WEIGHTS.get(t, 0.5) for t in predicted_attack_type]) * 100

    attack_prob_pct = np.clip(attack_probability, 0, 1) * 100
    anomaly_pct = np.clip(anomaly_score, 0, 100)

    threat_score = (
        0.35 * attack_prob_pct +
        0.25 * anomaly_pct +
        0.20 * freq_score +
        0.20 * severity_w
    )
    threat_score = np.clip(threat_score, 0, 100)

    df["frequency_score"] = np.round(freq_score, 2)
    df["severity_weight"] = np.round(severity_w, 2)
    df["threat_score"] = np.round(threat_score, 2)
    df["severity"] = [severity_bucket(s) for s in threat_score]

    return df
