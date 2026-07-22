"""Session-based auth: a login/logout/status blueprint + a before_request guard."""

import secrets

from flask import Blueprint, jsonify, request, session

from backend import config
from backend.limiter import limiter

# Reachable without an existing session — otherwise you could never log in.
AUTH_EXEMPT_PATHS = {"/api/auth/login", "/api/auth/status", "/api/auth/logout"}

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _credentials_valid(username, password):
    return secrets.compare_digest(username or "", config.AUTH_USERNAME) and secrets.compare_digest(
        password or "", config.AUTH_PASSWORD
    )


@auth_bp.route("/login", methods=["POST"])
@limiter.limit(config.LOGIN_RATE_LIMIT)
def login():
    data = request.get_json(silent=True) or {}
    if _credentials_valid(data.get("username"), data.get("password")):
        session.clear()
        session["authenticated"] = True
        session.permanent = True
        return jsonify({"authenticated": True})
    return jsonify({"error": "Invalid username or password."}), 401


@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"authenticated": False})


@auth_bp.route("/status")
def status():
    return jsonify({"authenticated": is_authenticated()})


def is_authenticated():
    return bool(session.get("authenticated"))


def enforce_auth():
    if not request.path.startswith("/api/"):
        return None
    if request.path in AUTH_EXEMPT_PATHS:
        return None
    if not is_authenticated():
        return jsonify({"error": "Authentication required."}), 401
    return None
