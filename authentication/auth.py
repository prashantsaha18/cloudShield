"""
CloudShield AI - Authentication
Handles registration, login, password hashing (bcrypt), and session state.
"""

import re
import bcrypt
import streamlit as st
from database import models


USERNAME_RE = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except (ValueError, AttributeError):
        return False


def validate_registration(username, email, password, confirm_password):
    """Returns (is_valid, error_message)."""
    if not USERNAME_RE.match(username or ""):
        return False, "Username must be 3-20 characters: letters, numbers, underscore only."
    if not EMAIL_RE.match(email or ""):
        return False, "Please enter a valid email address."
    if len(password or "") < 8:
        return False, "Password must be at least 8 characters."
    if password != confirm_password:
        return False, "Passwords do not match."
    if models.get_user_by_username(username):
        return False, "That username is already taken."
    if models.get_user_by_email(email):
        return False, "An account with that email already exists."
    return True, ""


def register_user(username, email, password, role="analyst"):
    password_hash = hash_password(password)
    user_id = models.create_user(username, email, password_hash, role=role)
    models.log_action(user_id, "register", f"New user registered: {username}")
    return user_id


def authenticate(username, password):
    """Returns the user dict on success, None on failure."""
    user = models.get_user_by_username(username)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None
    return user


def login_user(user):
    st.session_state["authenticated"] = True
    st.session_state["user_id"] = user["id"]
    st.session_state["username"] = user["username"]
    st.session_state["role"] = user["role"]
    models.log_action(user["id"], "login", f"{user['username']} logged in")


def logout_user():
    uid = st.session_state.get("user_id")
    if uid:
        models.log_action(uid, "logout", f"{st.session_state.get('username')} logged out")
    for key in ["authenticated", "user_id", "username", "role"]:
        st.session_state.pop(key, None)


def is_authenticated() -> bool:
    return bool(st.session_state.get("authenticated"))


def is_admin() -> bool:
    return st.session_state.get("role") == "admin"


def current_user_id():
    return st.session_state.get("user_id")


def current_username():
    return st.session_state.get("username")
