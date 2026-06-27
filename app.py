"""
CloudShield AI - Main Application Entry Point
Intelligent Threat Hunting & Security Analytics Platform.
"""

import importlib
import streamlit as st

st.set_page_config(
    page_title="CloudShield AI | Threat Hunting Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from database.db import init_db
from authentication import auth
from utils.theme import inject_theme, status_bar

# Initialize DB once per app process
init_db()
inject_theme()

# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------
for key, default in [
    ("authenticated", False),
    ("user_id", None),
    ("username", None),
    ("role", None),
    ("active_scan_id", None),
    ("active_results_df", None),
    ("active_metrics", None),
    ("active_dataset_name", None),
]:
    if key not in st.session_state:
        st.session_state[key] = default

# ---------------------------------------------------------------------------
# Navigation model. Deliberately ONE flat list driving ONE st.radio widget.
# This is the simplest design that cannot get into an inconsistent state:
# there's exactly one source of truth for "which page is active." Visual
# grouping is achieved by prefixing labels with a workflow-stage tag, which
# reads cleanly in a monospace sidebar font without needing multiple radio
# widgets that would otherwise have to be reconciled against each other.
# ---------------------------------------------------------------------------
NAV_ITEMS = [
    ("Home", "home"),
    ("Log Ingestion", "ingestion"),
    ("Preprocessing", "preprocessing_page"),
    ("Attack Detection", "detection_page"),
    ("Attack Classification", "classification_page"),
    ("Anomaly Detection", "anomaly_page"),
    ("Threat Scoring", "scoring_page"),
    ("Security Dashboard", "dashboard_page"),
    ("Visualization Center", "visualization_page"),
    ("Incident Reports", "reports_page"),
    ("Scan History", "history_page"),
    ("Export Center", "export_page"),
]
ADMIN_ITEM = ("Admin Panel", "admin_page")

PAGE_MODULES = {
    "home": "pages_content.home",
    "ingestion": "pages_content.ingestion",
    "preprocessing_page": "pages_content.preprocessing_page",
    "detection_page": "pages_content.detection_page",
    "classification_page": "pages_content.classification_page",
    "anomaly_page": "pages_content.anomaly_page",
    "scoring_page": "pages_content.scoring_page",
    "dashboard_page": "pages_content.dashboard_page",
    "visualization_page": "pages_content.visualization_page",
    "reports_page": "pages_content.reports_page",
    "history_page": "pages_content.history_page",
    "export_page": "pages_content.export_page",
    "admin_page": "pages_content.admin_page",
}


def render_login_register():
    col1, col2, col3 = st.columns([1, 1.3, 1])
    with col2:
        st.markdown("""
        <div style="text-align:center; margin-top:6vh; margin-bottom: 24px;">
            <div style="font-family:'JetBrains Mono',monospace; font-size:12px; letter-spacing:0.12em; color:#2DD4BF; margin-bottom:10px;">
                THREAT HUNTING &amp; SECURITY ANALYTICS PLATFORM
            </div>
            <div style="font-size:32px; font-weight:800; color:#E6E9EF;">
                🛡️ CloudShield <span style="color:#2DD4BF;">AI</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div class="csa-panel">', unsafe_allow_html=True)
        tab_login, tab_register = st.tabs(["LOGIN", "REGISTER"])

        with tab_login:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submitted = st.form_submit_button("Sign In", use_container_width=True, type="primary")
                if submitted:
                    if not username or not password:
                        st.error("Enter both username and password.")
                    else:
                        user = auth.authenticate(username, password)
                        if user:
                            auth.login_user(user)
                            st.rerun()
                        else:
                            st.error("Invalid username or password.")

        with tab_register:
            with st.form("register_form"):
                r_username = st.text_input("Choose a username")
                r_email = st.text_input("Email")
                r_password = st.text_input("Password", type="password")
                r_confirm = st.text_input("Confirm password", type="password")
                r_submitted = st.form_submit_button("Create Account", use_container_width=True, type="primary")
                if r_submitted:
                    from database import models
                    role = "admin" if models.count_users() == 0 else "analyst"
                    valid, error = auth.validate_registration(r_username, r_email, r_password, r_confirm)
                    if not valid:
                        st.error(error)
                    else:
                        auth.register_user(r_username, r_email, r_password, role=role)
                        st.success(
                            "Account created. "
                            + ("You're the first user, so you've been made Admin. " if role == "admin" else "")
                            + "Sign in from the Login tab."
                        )
        st.markdown('</div>', unsafe_allow_html=True)
        st.caption("First registered account on this deployment becomes Admin automatically.")


def render_sidebar():
    items = list(NAV_ITEMS)
    if auth.is_admin():
        items.append(ADMIN_ITEM)
    labels = [label for label, _ in items]

    with st.sidebar:
        st.markdown("""
        <div style="padding: 4px 0 14px 0;">
            <span style="font-size:18px; font-weight:800;">🛡️ CloudShield</span>
            <span style="font-size:18px; font-weight:800; color:#2DD4BF;"> AI</span>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(
            '<div class="csa-mono-label" style="margin:0 0 4px 2px;">NAVIGATE</div>',
            unsafe_allow_html=True,
        )
        choice = st.radio("Navigate", labels, label_visibility="collapsed", key="nav_radio")

        st.markdown('<div class="csa-divider"></div>', unsafe_allow_html=True)
        st.caption(f"{auth.current_username()} · {st.session_state.get('role')}")
        if st.button("Sign Out", use_container_width=True, type="secondary"):
            auth.logout_user()
            st.rerun()

    module_key = dict(items)[choice]
    return choice, module_key


def main():
    if not auth.is_authenticated():
        render_login_register()
        return

    label, module_key = render_sidebar()

    status_bar(
        username=auth.current_username(),
        role=st.session_state.get("role"),
        scan_loaded=bool(st.session_state.get("active_scan_id")),
    )

    module = importlib.import_module(PAGE_MODULES[module_key])
    module.render()


if __name__ == "__main__":
    main()
