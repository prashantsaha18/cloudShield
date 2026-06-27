"""
CloudShield AI - Model Training
Trains:
  1. Binary attack detectors (Random Forest + XGBoost) -> Normal vs Attack
  2. Multiclass attack classifier (Random Forest) -> attack type
  3. Isolation Forest anomaly detector

All models are trained on-the-fly from the uploaded/generated dataset since
this is a portfolio/demo tool, not a system with a fixed labeled training
corpus. Models are cached in Streamlit session state per scan.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix,
)
from sklearn.preprocessing import LabelEncoder
import xgboost as xgb

from preprocessing.preprocess import get_feature_matrix


def train_attack_detection(df_clean: pd.DataFrame):
    """
    Binary classification: Normal vs Attack.
    Returns a dict with trained models, metrics, and test split predictions.
    """
    X, feature_cols = get_feature_matrix(df_clean)
    y = (df_clean["attack_type"] != "Normal").astype(int).values  # 1 = Attack

    # Guard against a degenerate single-class dataset (e.g. user uploads all-normal logs)
    if len(np.unique(y)) < 2:
        return {
            "warning": "Dataset contains only one class (all Normal or all Attack). "
                       "Detection metrics require both classes; upload a more varied dataset "
                       "or use the synthetic generator.",
            "rf_model": None, "xgb_model": None, "metrics": {}, "feature_cols": feature_cols,
        }

    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X, y, np.arange(len(y)), test_size=0.25, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(n_estimators=80, max_depth=10, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)[:, 1]

    xgb_model = xgb.XGBClassifier(
        n_estimators=100, max_depth=5, learning_rate=0.15,
        eval_metric="logloss", random_state=42, n_jobs=-1,
    )
    xgb_model.fit(X_train, y_train)
    xgb_pred = xgb_model.predict(X_test)
    xgb_proba = xgb_model.predict_proba(X_test)[:, 1]

    def metrics_for(y_true, y_pred):
        return {
            "accuracy": round(float(accuracy_score(y_true, y_pred)), 4),
            "precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
        }

    # Final ensemble probability used downstream = average of RF + XGB on FULL dataset
    rf_full_proba = rf.predict_proba(X)[:, 1]
    xgb_full_proba = xgb_model.predict_proba(X)[:, 1]
    ensemble_proba = (rf_full_proba + xgb_full_proba) / 2.0
    ensemble_pred = (ensemble_proba >= 0.5).astype(int)

    return {
        "rf_model": rf,
        "xgb_model": xgb_model,
        "feature_cols": feature_cols,
        "metrics": {
            "random_forest": metrics_for(y_test, rf_pred),
            "xgboost": metrics_for(y_test, xgb_pred),
        },
        "ensemble_proba": ensemble_proba,   # aligned with df_clean row order
        "ensemble_pred": ensemble_pred,
        "warning": None,
    }


def train_attack_classification(df_clean: pd.DataFrame, attack_mask: np.ndarray):
    """
    Multiclass classification of attack type. `attack_mask` selects which
    rows to train on - callers should pass ground-truth labeled attack rows
    (df_clean['attack_type'] != 'Normal') when a labeled attack_type column
    is available, since training on detector-predicted rows mixes in false
    positives still labeled 'Normal' and degrades the class label set.
    Falls back gracefully on very small attack samples.
    """
    X, feature_cols = get_feature_matrix(df_clean)
    y_labels = df_clean["attack_type"].values

    attack_idx = np.where(attack_mask)[0]
    if len(attack_idx) < 10 or len(np.unique(y_labels[attack_idx])) < 2:
        return {
            "warning": "Not enough labeled attack diversity to train a reliable classifier. "
                       "Probability scores shown are heuristic, not model-based.",
            "model": None, "label_encoder": None,
        }

    X_attacks = X[attack_idx]
    y_attacks = y_labels[attack_idx]

    le = LabelEncoder()
    y_enc = le.fit_transform(y_attacks)

    # Some classes may have very few samples; skip stratify if it would fail
    try:
        X_train, X_test, y_train, y_test = train_test_split(
            X_attacks, y_enc, test_size=0.25, random_state=42, stratify=y_enc
        )
    except ValueError:
        X_train, X_test, y_train, y_test = train_test_split(
            X_attacks, y_enc, test_size=0.25, random_state=42
        )

    clf = RandomForestClassifier(n_estimators=80, max_depth=10, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report_metrics = {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
    }

    # Predict probabilities for ALL rows in the full dataset (not just test split)
    all_proba = clf.predict_proba(X)
    class_names = le.classes_

    return {
        "model": clf,
        "label_encoder": le,
        "class_names": class_names,
        "all_proba": all_proba,        # shape (n_rows, n_classes), aligned with df_clean
        "metrics": report_metrics,
        "warning": None,
    }


def train_anomaly_detection(df_clean: pd.DataFrame, contamination=0.1):
    """Isolation Forest anomaly detector. Returns anomaly scores normalized to 0-100."""
    X, feature_cols = get_feature_matrix(df_clean)

    iso = IsolationForest(
        n_estimators=100, contamination=contamination, random_state=42, n_jobs=-1
    )
    iso.fit(X)

    raw_scores = iso.decision_function(X)  # higher = more normal
    # Invert and normalize to 0-100 where 100 = most anomalous
    inverted = -raw_scores
    min_v, max_v = inverted.min(), inverted.max()
    if max_v - min_v < 1e-9:
        normalized = np.zeros_like(inverted)
    else:
        normalized = (inverted - min_v) / (max_v - min_v) * 100

    predictions = iso.predict(X)  # -1 = anomaly, 1 = normal

    return {
        "model": iso,
        "anomaly_scores": normalized,        # aligned with df_clean rows
        "is_anomaly": predictions == -1,
    }
