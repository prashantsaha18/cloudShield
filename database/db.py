"""
CloudShield AI - Database Layer
Handles SQLite connection, schema creation, and low-level persistence.
Uses a single file-based SQLite DB stored relative to the app root so it
works on Streamlit Cloud's ephemeral filesystem without any external service.
"""

import sqlite3
import os
import threading
from contextlib import contextmanager

# Resolve DB path relative to this file so it works regardless of CWD
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "cloudshield.db")

# SQLite + Streamlit's multi-threaded script runner needs a lock to avoid
# "database is locked" errors under concurrent reruns.
_db_lock = threading.Lock()


@contextmanager
def get_connection():
    """Context manager yielding a SQLite connection with row access by name."""
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables if they do not already exist. Safe to call every app start."""
    with _db_lock:
        with get_connection() as conn:
            cur = conn.cursor()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'analyst',
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    dataset_name TEXT NOT NULL,
                    scan_date TEXT NOT NULL DEFAULT (datetime('now')),
                    total_logs INTEGER DEFAULT 0,
                    threat_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    report_json TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    timestamp TEXT,
                    source_ip TEXT,
                    destination_ip TEXT,
                    protocol TEXT,
                    bytes_sent REAL,
                    bytes_received REAL,
                    connection_duration REAL,
                    predicted_label TEXT,
                    attack_type TEXT,
                    attack_type_predicted TEXT,
                    attack_type_confidence REAL,
                    attack_probability REAL,
                    anomaly_score REAL,
                    is_anomaly INTEGER,
                    frequency_score REAL,
                    severity_weight REAL,
                    threat_score REAL,
                    severity TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS incident_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    incident_id TEXT NOT NULL,
                    threat_type TEXT,
                    severity TEXT,
                    affected_assets TEXT,
                    recommended_actions TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
            """)

            conn.commit()


def execute(query, params=()):
    """Run a write query (INSERT/UPDATE/DELETE) and return the lastrowid."""
    with _db_lock:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return cur.lastrowid


def executemany(query, param_list):
    with _db_lock:
        with get_connection() as conn:
            cur = conn.cursor()
            cur.executemany(query, param_list)


def fetch_all(query, params=()):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]


def fetch_one(query, params=()):
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None
