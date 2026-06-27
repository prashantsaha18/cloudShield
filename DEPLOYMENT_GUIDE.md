# Deployment Guide — Streamlit Community Cloud

## 1. Push to GitHub

```bash
cd CloudShieldAI
git init
git add .
git commit -m "Initial commit: CloudShield AI"
git branch -M main
git remote add origin https://github.com/<your-username>/CloudShieldAI.git
git push -u origin main
```

> **Do not** rename or delete `requirements.txt` or `runtime.txt` — Streamlit Cloud reads these automatically to set up the environment.

## 2. Deploy on Streamlit Cloud

1. Go to [share.streamlit.io](https://share.streamlit.io) and sign in with GitHub.
2. Click **"New app"**.
3. Select your repository, branch (`main`), and set **Main file path** to `app.py`.
4. Click **Deploy**.

The first deploy will take a few minutes while it installs dependencies from `requirements.txt`.

## 3. Why this app deploys cleanly (and what to check if it doesn't)

This project was built to avoid the most common Streamlit Cloud failure modes:

- **Pinned, mutually-compatible versions** in `requirements.txt` (not floating `>=` ranges). `numpy==1.26.4` is deliberately pinned below the newest releases, since scikit-learn/XGBoost wheel compatibility lags behind numpy's latest majors — this is the single most common cause of `uv` resolver failures and `ImportError: numpy.core.multiarray` crashes on Cloud.
- **`runtime.txt` pins Python 3.11** so the container doesn't pick a newer Python than the pinned wheels support.
- **No system-level dependencies.** Everything (SQLite, bcrypt, ReportLab) installs from pure Python wheels — no `apt-get` packages, no Docker, no compiler toolchain required.
- **No paid APIs or external services.** All ML runs in-process; the database is a local SQLite file; there's no required environment variable or secret for the core app to function.
- **All file paths are relative** (resolved via `os.path.dirname(__file__)` in `database/db.py`), so the app works regardless of the working directory Streamlit Cloud launches it from.

If you still hit a dependency resolution error on Cloud:

1. Open your app's **Manage app → logs** to see the exact failing package/line.
2. Try clearing the build cache: **Manage app → Reboot app** (sometimes a stale cache causes a mismatched resolve).
3. As a last resort, you can strip back to only Streamlit's pre-installed packages (`streamlit`, `pandas`, `numpy`, `altair`) and reintroduce the others one at a time — but this should not be necessary with the pinned versions provided here.

## 4. First-time setup after deploying

1. Open your deployed app URL.
2. Register an account — **the first registered user is automatically made Admin.**
3. Go to **📥 Log Ingestion** → **Generate Synthetic Dataset** to get started immediately without needing your own data.
4. Walk through **Preprocessing → Attack Detection → Attack Classification → Anomaly Detection → Threat Scoring** in order — each stage depends on the previous one having been run in the current session.
5. View results on **📊 Security Dashboard** and **🗺️ Visualization Center**, generate a report on **📄 Incident Reports**, and download data from **📤 Export Center**.

## 5. Persistence caveat

Streamlit Cloud containers can restart (on redeploy, inactivity, or maintenance). Since this app uses a local SQLite file for storage, **user accounts and scan history will reset when that happens.** This is intentional for a self-contained, zero-config demo. If you need durable persistence across container restarts for a real interview demo, the cleanest fix is swapping the SQLite connection in `database/db.py` for a managed Postgres database (e.g. Neon) — the rest of the codebase talks to `database/models.py`, so only the connection layer needs to change.

## 6. Updating the app

Any push to your connected branch will trigger an automatic redeploy on Streamlit Cloud. To pin further dependency updates safely, test them locally first with:

```bash
python -m venv venv_test
source venv_test/bin/activate
pip install -r requirements.txt
streamlit run app.py
```
