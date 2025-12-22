import logging
import time
from datetime import datetime
from flask import Blueprint, render_template, jsonify, current_app, request
from ..utils import require_auth, _format_uptime, require_api_auth 

main_bp = Blueprint('main', __name__, url_prefix='/')

@main_bp.route("/")
@require_auth
def index():
    """Main page route."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    db = current_app.config.get("DB")

    if auth_enabled and db:
        if not db.has_users():
            return redirect(url_for("auth.setup"))

        session_token = request.cookies.get("session_token")
        user = db.get_user_by_session(session_token)
        return render_template("index.html", user=user, auth_enabled=True)
    else:
        return render_template("index.html", auth_enabled=False)

@main_bp.route("/health")
def health():
    """Health check endpoint."""
    return jsonify(
        {"status": "healthy", "timestamp": datetime.now().isoformat()}
    )

@main_bp.route("/api/info")
@require_api_auth 
def api_info():
    """API info endpoint."""
    start_time = current_app.config.get("START_TIME", time.time())
    uptime_seconds = int(time.time() - start_time)
    uptime_str = _format_uptime(uptime_seconds)

    latest_version = getattr(current_app.config["CONFIG"], "LATEST_VERSION", None)
    if latest_version is not None:
        latest_version = str(latest_version)

    return jsonify(
        {
            "version": current_app.config["CONFIG"].VERSION,
            "status": "running",
            "uptime": uptime_str,
            "latest_version": latest_version,
            "is_newest": getattr(current_app.config["CONFIG"], "IS_NEWEST_VERSION", True),
            "supported_providers": list(current_app.config["CONFIG"].SUPPORTED_PROVIDERS),
            "platform": current_app.config["CONFIG"].PLATFORM_SYSTEM,
        }
    )

@main_bp.route("/api/test")
@require_api_auth
def api_test():
    """API test endpoint."""
    return jsonify(
        {
            "status": "success",
            "message": "Connection test successful",
            "timestamp": datetime.now().isoformat(),
            "version": current_app.config["CONFIG"].VERSION,
        }
    )