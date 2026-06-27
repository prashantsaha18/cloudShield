"""
CloudShield AI - Data Models
High-level data access functions used by the rest of the app. Keeps all
SQL out of UI code.
"""

import json
from datetime import datetime
from database.db import execute, fetch_all, fetch_one


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def create_user(username, email, password_hash, role="analyst"):
    return execute(
        "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
        (username, email, password_hash, role),
    )


def get_user_by_username(username):
    return fetch_one("SELECT * FROM users WHERE username = ?", (username,))


def get_user_by_email(email):
    return fetch_one("SELECT * FROM users WHERE email = ?", (email,))


def get_user_by_id(user_id):
    return fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))


def list_all_users():
    return fetch_all("SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC")


def count_users():
    row = fetch_one("SELECT COUNT(*) as c FROM users")
    return row["c"] if row else 0


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def create_scan(user_id, dataset_name, total_logs, threat_count, critical_count, report_obj=None):
    return execute(
        """INSERT INTO scans (user_id, dataset_name, total_logs, threat_count, critical_count, report_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (user_id, dataset_name, total_logs, threat_count, critical_count,
         json.dumps(report_obj) if report_obj else None),
    )


def get_scans_for_user(user_id):
    return fetch_all("SELECT * FROM scans WHERE user_id = ? ORDER BY scan_date DESC", (user_id,))


def get_scan_by_id(scan_id):
    return fetch_one("SELECT * FROM scans WHERE id = ?", (scan_id,))


def get_all_scans():
    return fetch_all("""
        SELECT scans.*, users.username
        FROM scans JOIN users ON scans.user_id = users.id
        ORDER BY scan_date DESC
    """)


def delete_scan(scan_id):
    execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def count_scans():
    row = fetch_one("SELECT COUNT(*) as c FROM scans")
    return row["c"] if row else 0


def sum_threats():
    row = fetch_one("SELECT COALESCE(SUM(threat_count),0) as c FROM scans")
    return row["c"] if row else 0


# ---------------------------------------------------------------------------
# Scan events (per-row predictions, kept for history/leaderboard/forecasting)
# ---------------------------------------------------------------------------

def bulk_insert_events(scan_id, events_df):
    """events_df: pandas DataFrame with the expected columns (output of models.predict.run_full_pipeline)."""
    from database.db import executemany
    rows = []
    for _, r in events_df.iterrows():
        rows.append((
            scan_id,
            str(r.get("timestamp", "")),
            str(r.get("source_ip", "")),
            str(r.get("destination_ip", "")),
            str(r.get("protocol", "")),
            float(r.get("bytes_sent", 0) or 0),
            float(r.get("bytes_received", 0) or 0),
            float(r.get("connection_duration", 0) or 0),
            str(r.get("predicted_label", "")),
            str(r.get("attack_type", "")),
            str(r.get("attack_type_predicted", "")),
            float(r.get("attack_type_confidence", 0) or 0),
            float(r.get("attack_probability", 0) or 0),
            float(r.get("anomaly_score", 0) or 0),
            int(bool(r.get("is_anomaly", False))),
            float(r.get("frequency_score", 0) or 0),
            float(r.get("severity_weight", 0) or 0),
            float(r.get("threat_score", 0) or 0),
            str(r.get("severity", "")),
        ))
    executemany(
        """INSERT INTO scan_events
           (scan_id, timestamp, source_ip, destination_ip, protocol, bytes_sent,
            bytes_received, connection_duration, predicted_label, attack_type,
            attack_type_predicted, attack_type_confidence, attack_probability,
            anomaly_score, is_anomaly, frequency_score, severity_weight,
            threat_score, severity)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        rows,
    )


def get_events_for_scan(scan_id):
    return fetch_all("SELECT * FROM scan_events WHERE scan_id = ?", (scan_id,))


def get_top_source_ips(limit=10):
    return fetch_all("""
        SELECT source_ip, COUNT(*) as count
        FROM scan_events
        WHERE predicted_label = 'Attack'
        GROUP BY source_ip ORDER BY count DESC LIMIT ?
    """, (limit,))


# ---------------------------------------------------------------------------
# Incident reports
# ---------------------------------------------------------------------------

def create_incident_report(scan_id, incident_id, threat_type, severity, affected_assets, recommended_actions):
    return execute(
        """INSERT INTO incident_reports
           (scan_id, incident_id, threat_type, severity, affected_assets, recommended_actions)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (scan_id, incident_id, threat_type, severity, affected_assets,
         json.dumps(recommended_actions)),
    )


def get_reports_for_scan(scan_id):
    return fetch_all("SELECT * FROM incident_reports WHERE scan_id = ?", (scan_id,))


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

def log_action(user_id, action, details=""):
    execute(
        "INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)",
        (user_id, action, details),
    )


def get_recent_audit_log(limit=100):
    return fetch_all("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT ?", (limit,))
