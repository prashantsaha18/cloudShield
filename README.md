# 🛡️ CloudShield AI
### Intelligent Threat Hunting & Security Analytics Platform

CloudShield AI is a full-stack, ML-powered cybersecurity analytics platform built with Streamlit. It ingests network/security logs, detects and classifies attacks, scores threats, visualizes findings on a SOC-style dashboard, and generates downloadable incident reports — all deployable directly to Streamlit Community Cloud with no external services required.

Built as a final-year CSE major project / placement portfolio piece.

---

## ✨ Features

| Module | Description |
|---|---|
| **Authentication** | Registration, login, bcrypt password hashing, session management. First registered user becomes Admin. |
| **Log Ingestion** | Upload CSV logs, or generate a realistic synthetic dataset (no external download required). Files are capped at 15,000 rows to keep scoring fast. |
| **Preprocessing** | Missing value handling, label encoding, feature scaling, outlier detection (IQR), deduplication, data quality report. |
| **Attack Detection** | Binary Normal-vs-Attack classification using an ensemble of Random Forest + XGBoost, with accuracy/precision/recall/F1/confusion matrix. |
| **Attack Classification** | Multiclass classification into DDoS, DoS, Brute Force, Port Scan, SQL Injection, Botnet, Malware, Phishing, Unknown Threat — with probability scores. |
| **Anomaly Detection** | Isolation Forest flags suspicious/unusual traffic independent of labeled attack types. |
| **Threat Scoring Engine** | Composite 0–100 threat score (attack probability + anomaly score + frequency + severity weight), bucketed into Low/Medium/High/Critical with a visual Threat Meter. |
| **Security Dashboard** | KPIs, threat distribution, attack timeline, attack type breakdown, top source/destination IPs. |
| **Visualization Center** | Attack heatmap (day × hour), network traffic scatter analysis, threat leaderboard, simple linear-trend attack forecast. |
| **AI Incident Report Generator** | SOC-style incident records grouped by threat type/severity with recommended remediation actions; downloadable PDF. |
| **Scan History** | Every scan is persisted to SQLite; reload any past scan into the dashboard/reports/export views. |
| **Export Center** | Export results as CSV, Excel, JSON, or a one-page Executive Summary PDF. |
| **Admin Panel** | Platform-wide stats, user list, all-scans view with delete capability, audit log. |

## 🎨 Design

The UI follows a console-grade visual identity modeled on real analyst tooling (SIEM/EDR consoles) rather than a generic dashboard template: a near-black slate palette, hairline borders, monospace (`JetBrains Mono`) for every data value — IDs, IPs, scores, timestamps — paired with `Inter` for prose and navigation. Color is reserved strictly for severity signal (critical/high/medium/low), so it reads as meaningful status rather than decoration. The persistent top status bar (`DATABASE: ONLINE · SCAN LOADED · USER · ROLE`) is the signature element, echoing the kind of system-status strip found in tools like Splunk or CrowdStrike Falcon.

---

## 🧱 Tech Stack

- **Frontend:** Streamlit (custom dark SOC-themed UI)
- **ML:** scikit-learn (Random Forest, Isolation Forest), XGBoost
- **Data:** Pandas, NumPy
- **Visualization:** Plotly
- **Database:** SQLite (file-based, zero external dependency)
- **Auth:** bcrypt password hashing
- **Reports/Exports:** ReportLab (PDF), openpyxl (Excel)

---

## 📁 Project Structure

```
CloudShieldAI/
├── app.py                      # Main entry point, routing, auth gate
├── requirements.txt            # Pinned dependencies
├── runtime.txt                 # Pinned Python version (3.11)
├── .streamlit/config.toml      # Theme + server config
├── database/
│   ├── db.py                   # SQLite connection + schema
│   └── models.py                # Data access layer
├── authentication/
│   └── auth.py                  # Register/login/hashing/session
├── preprocessing/
│   ├── preprocess.py            # Cleaning, encoding, scaling
│   └── synthetic_data.py         # Synthetic dataset generator
├── models/
│   ├── train.py                  # RF + XGBoost + Isolation Forest training
│   ├── scoring.py                # Threat scoring engine
│   └── predict.py                # Full pipeline orchestration
├── dashboard/
│   └── dashboard.py               # All chart-rendering functions
├── reports/
│   └── report_generator.py        # Incident records + PDF report
├── exports/
│   └── export.py                   # CSV/Excel/JSON/PDF export helpers
├── utils/
│   └── theme.py                    # Dark theme CSS + Plotly helpers
├── pages_content/                  # One file per sidebar page
├── datasets/
│   └── sample_security_logs.csv     # Bundled sample dataset
└── saved_models/                    # (reserved for future model persistence)
```

---

## 🚀 Running Locally

```bash
pip install -r requirements.txt
streamlit run app.py
```

The first user you register is automatically made an **Admin**.

## 📊 Expected CSV Schema

If uploading your own logs, the CSV needs these columns:

```
timestamp, source_ip, destination_ip, protocol, bytes_sent, bytes_received, connection_duration
```

`attack_type` is optional — if present (with a `Normal` label for benign traffic), it is used as ground truth to train the attack classifier. If absent, the platform still runs but explains via on-screen warnings that classification falls back to heuristics. A sample file is available for download from the **Log Ingestion** page, or at `datasets/sample_security_logs.csv`.

## ☁️ Deploying to Streamlit Cloud

See `DEPLOYMENT_GUIDE.md` for full instructions.

## ⚠️ Notes & Limitations

- This is a **portfolio/demo platform**. Models are trained on-the-fly from the uploaded/generated dataset each session rather than on a fixed labeled corpus — this keeps the tool self-contained and deployable without external data downloads, but means metrics reflect in-session performance, not a benchmark against NSL-KDD/CIC-IDS leaderboards.
- SQLite data (`database/cloudshield.db`) lives in Streamlit Cloud's ephemeral container filesystem. It persists across reruns within an active app instance but **will reset on app reboot/redeploy**. For permanent multi-session persistence, swap in a managed Postgres (e.g. Neon) — the `database/db.py` connection layer is small and isolated for an easy swap.
- The attack forecast on the Visualization Center page is a simple linear-trend heuristic for illustrative purposes, clearly labeled as such — not a calibrated time-series model.
- Datasets are capped at 15,000 rows per scan (`MAX_ROWS` in `preprocessing/preprocess.py`). The full pipeline trains four tree-ensemble models synchronously in one rerun; beyond this size, training time risks feeling sluggish on a shared/free-tier CPU. Larger uploads are truncated with an on-screen notice rather than left to hang.
