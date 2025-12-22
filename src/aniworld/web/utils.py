import logging
from functools import wraps
from datetime import datetime
from flask import request, session, redirect, url_for, jsonify, current_app


def _format_uptime(seconds: int) -> str:
    """Format uptime in human readable format."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        seconds = seconds % 60
        return f"{minutes}m {seconds}s"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        return f"{hours}h {minutes}m {seconds}s"


# Removed _get_user_from_session_token as it was not used by decorators.


def require_api_auth(f):
    """Decorator to require authentication for API routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_enabled = current_app.config.get("AUTH_ENABLED", False)
        db = current_app.config.get("DB")

        if not auth_enabled:
            return f(*args, **kwargs)

        if not db:
            logging.error("Authentication database not available but auth is enabled.")
            return jsonify({"error": "Authentication database not available"}), 500

        session_token = request.cookies.get("session_token")
        if not session_token:
            return jsonify({"error": "Authentication required"}), 401

        user = db.get_user_by_session(session_token)
        if not user:
            return jsonify({"error": "Invalid session"}), 401

        return f(*args, **kwargs)
    return decorated_function


def require_auth(f):
    """Decorator to require authentication for HTML routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_enabled = current_app.config.get("AUTH_ENABLED", False)
        db = current_app.config.get("DB")

        if not auth_enabled:
            return f(*args, **kwargs)

        if not db:
            logging.error("Authentication database not available but auth is enabled.")
            return redirect(url_for("auth.login"))

        # Check for session token in cookies
        session_token = request.cookies.get("session_token")
        if not session_token:
            return redirect(url_for("auth.login"))

        user = db.get_user_by_session(session_token)
        if not user:
            return redirect(url_for("auth.login"))

        # Store user info in Flask session for templates
        session["user"] = user
        return f(*args, **kwargs)
    return decorated_function


def require_admin(f):
    """Decorator to require admin privileges for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_enabled = current_app.config.get("AUTH_ENABLED", False)
        db = current_app.config.get("DB")

        if not auth_enabled:
            return f(*args, **kwargs)

        if not db:
            logging.error("Authentication database not available but auth is enabled.")
            return jsonify({"error": "Authentication database not available"}), 500

        session_token = request.cookies.get("session_token")
        if not session_token:
            return redirect(url_for("auth.login"))

        user = db.get_user_by_session(session_token)
        if not user or not user["is_admin"]:
            return jsonify({"error": "Admin access required"}), 403

        session["user"] = user
        return f(*args, **kwargs)
    return decorated_function