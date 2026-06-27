"""
CloudShield AI - Preprocessing
Validates uploaded logs, handles missing values, encodes categoricals,
scales features, flags outliers/duplicates, and produces a data quality report.
"""

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler

REQUIRED_COLUMNS = [
    "timestamp", "source_ip", "destination_ip", "protocol",
    "bytes_sent", "bytes_received", "connection_duration",
]
OPTIONAL_COLUMNS = ["attack_type"]
NUMERIC_COLUMNS = ["bytes_sent", "bytes_received", "connection_duration"]

# Hard cap on dataset size processed in a single scan. The full pipeline trains
# four tree-ensemble models synchronously inside one Streamlit rerun; beyond
# this row count, training time risks exceeding what's comfortable on a
# shared/free-tier CPU (e.g. Streamlit Community Cloud). Larger files are
# truncated with a clear on-screen notice rather than silently hanging.
MAX_ROWS = 15000


def validate_csv(df: pd.DataFrame):
    """Check required columns and types. Returns (is_valid, list_of_issues)."""
    issues = []

    missing_cols = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing_cols:
        issues.append(f"Missing required columns: {', '.join(missing_cols)}")
        return False, issues

    for col in NUMERIC_COLUMNS:
        non_numeric = pd.to_numeric(df[col], errors="coerce").isna() & df[col].notna()
        if non_numeric.any():
            issues.append(f"Column '{col}' has {int(non_numeric.sum())} non-numeric values that will be coerced.")

    null_counts = df[REQUIRED_COLUMNS].isna().sum()
    for col, count in null_counts.items():
        if count > 0:
            issues.append(f"Column '{col}' has {int(count)} missing values.")

    if df.empty:
        issues.append("Uploaded file contains no rows.")
        return False, issues

    return True, issues


def build_quality_report(df: pd.DataFrame, df_clean: pd.DataFrame) -> dict:
    return {
        "original_rows": int(len(df)),
        "cleaned_rows": int(len(df_clean)),
        "duplicates_removed": int(len(df) - df["__dup_check__"].nunique()) if "__dup_check__" in df.columns else 0,
        "missing_values_filled": int(df[REQUIRED_COLUMNS].isna().sum().sum()),
        "outliers_flagged": int(df_clean["is_outlier"].sum()) if "is_outlier" in df_clean.columns else 0,
        "columns": list(df.columns),
    }


def preprocess(df: pd.DataFrame):
    """
    Full preprocessing pipeline:
    - coerce numeric columns
    - fill missing values
    - remove exact duplicates
    - flag outliers (IQR method) on numeric columns
    - label-encode protocol
    - scale numeric features (for model input; original values preserved separately)

    Returns: (df_clean, encoders, scaler, quality_report)
    """
    df = df.copy()
    original_len = len(df)

    # Coerce numerics
    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Track missing before fill
    missing_before = df[REQUIRED_COLUMNS].isna().sum().sum()

    # Fill missing values
    for col in NUMERIC_COLUMNS:
        df[col] = df[col].fillna(df[col].median() if df[col].notna().any() else 0)
    for col in ["source_ip", "destination_ip", "protocol"]:
        df[col] = df[col].fillna("unknown")
    df["timestamp"] = df["timestamp"].ffill().bfill()

    if "attack_type" not in df.columns:
        df["attack_type"] = "Unknown"
    df["attack_type"] = df["attack_type"].fillna("Unknown")

    # Remove exact duplicates
    dedup_cols = REQUIRED_COLUMNS
    before_dedup = len(df)
    df = df.drop_duplicates(subset=dedup_cols, keep="first").reset_index(drop=True)
    duplicates_removed = before_dedup - len(df)

    # Outlier flagging via IQR on numeric cols
    df["is_outlier"] = False
    for col in NUMERIC_COLUMNS:
        q1, q3 = df[col].quantile(0.25), df[col].quantile(0.75)
        iqr = q3 - q1
        lower, upper = q1 - 1.5 * iqr, q3 + 1.5 * iqr
        df["is_outlier"] = df["is_outlier"] | (df[col] < lower) | (df[col] > upper)

    # Label encode protocol for model use
    encoders = {}
    protocol_encoder = LabelEncoder()
    df["protocol_encoded"] = protocol_encoder.fit_transform(df["protocol"].astype(str))
    encoders["protocol"] = protocol_encoder

    # Scale numeric features (kept separate from original display columns)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(df[NUMERIC_COLUMNS])
    for i, col in enumerate(NUMERIC_COLUMNS):
        df[f"{col}_scaled"] = scaled[:, i]

    quality_report = {
        "original_rows": int(original_len),
        "cleaned_rows": int(len(df)),
        "duplicates_removed": int(duplicates_removed),
        "missing_values_filled": int(missing_before),
        "outliers_flagged": int(df["is_outlier"].sum()),
        "columns": list(df.columns),
    }

    return df, encoders, scaler, quality_report


def get_feature_matrix(df: pd.DataFrame):
    """Return the numeric feature matrix used for model training/inference."""
    feature_cols = [f"{c}_scaled" for c in NUMERIC_COLUMNS] + ["protocol_encoded"]
    return df[feature_cols].values, feature_cols
