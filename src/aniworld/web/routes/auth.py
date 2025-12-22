import logging
from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, current_app
from ..utils import require_api_auth, require_admin, require_auth 

auth_bp = Blueprint('auth', __name__, url_prefix='/')

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login page route."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    if not db.has_users():
        return redirect(url_for("auth.setup"))

    if request.method == "POST":
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify(
                {"success": False, "error": "Username and password required"}
            ), 400

        user = db.verify_user(username, password)
        if user:
            session_token = db.create_session(user["id"])
            response = jsonify({"success": True, "redirect": url_for("main.index")})
            response.set_cookie(
                "session_token",
                session_token,
                httponly=True,
                secure=False,
                max_age=30 * 24 * 60 * 60,
            )
            return response
        else:
            return jsonify(
                {"success": False, "error": "Invalid credentials"}
            ), 401

    return render_template("login.html")

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Logout route."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    session_token = request.cookies.get("session_token")
    if session_token:
        db.delete_session(session_token)

    response = jsonify({"success": True, "redirect": url_for("auth.login")})
    response.set_cookie("session_token", "", expires=0)
    return response

@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """First-time setup route for creating admin user."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    if db.has_users():
        return redirect(url_for("main.index"))

    if request.method == "POST":
        data = request.get_json()
        username = data.get("username", "").strip()
        password = data.get("password", "")

        if not username or not password:
            return jsonify(
                {"success": False, "error": "Username and password required"}
            ), 400

        if len(password) < 6:
            return jsonify(
                {
                    "success": False,
                    "error": "Password must be at least 6 characters",
                }
            ), 400

        if db.create_user(
            username, password, is_admin=True, is_original_admin=True
        ):
            return jsonify(
                {
                    "success": True,
                    "message": "Admin user created successfully",
                    "redirect": url_for("auth.login"),
                }
            )
        else:
            return jsonify(
                {"success": False, "error": "Failed to create user"}
            ), 500

    return render_template("setup.html")

@auth_bp.route("/settings")
@require_auth 
def settings():
    """Settings page route."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    session_token = request.cookies.get("session_token")
    user = db.get_user_by_session(session_token)
    users = db.get_all_users() if user and user["is_admin"] else []

    return render_template("settings.html", user=user, users=users)

@auth_bp.route("/api/users", methods=["GET"])
@require_admin
def api_get_users():
    """Get all users (admin only)."""
    db = current_app.config.get("DB")
    if not db:
        return jsonify(
            {"success": False, "error": "Authentication not available"}
        ), 500
    users = db.get_all_users()
    return jsonify({"success": True, "users": users})

@auth_bp.route("/api/users", methods=["POST"])
@require_admin
def api_create_user():
    """Create new user (admin only)."""
    db = current_app.config.get("DB")
    data = request.get_json()

    if not data:
        return jsonify(
            {"success": False, "error": "No JSON data received"}
        ), 400

    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    is_admin = data.get("is_admin", False)

    if not username or not password:
        return jsonify(
            {
                "success": False,
                "error": f'Username and password required. Got username: "{username}", password: "{password}"',
            }
        ), 400

    if len(password) < 6:
        return jsonify(
            {
                "success": False,
                "error": "Password must be at least 6 characters",
            }
        ), 400

    if not db:
        return jsonify(
            {"success": False, "error": "Authentication not available"}
        ), 500

    if db.create_user(username, password, is_admin):
        return jsonify(
            {"success": True, "message": "User created successfully"}
        )
    else:
        return jsonify(
            {
                "success": False,
                "error": "Failed to create user (username may already exist)",
            }
        ), 400

@auth_bp.route("/api/users/<int:user_id>", methods=["DELETE"])
@require_admin
def api_delete_user(user_id):
    """Delete user (admin only)."""
    db = current_app.config.get("DB")
    if not db:
        return jsonify(
            {"success": False, "error": "Authentication not available"}
        ), 500

    # Get user info to check if it's the original admin
    users = db.get_all_users()
    user_to_delete = next((u for u in users if u["id"] == user_id), None)

    if user_to_delete and user_to_delete.get("is_original_admin"):
        return jsonify(
            {"success": False, "error": "Cannot delete the original admin user"}
        ), 400

    if db.delete_user(user_id):
        return jsonify(
            {"success": True, "message": "User deleted successfully"}
        )
    else:
        return jsonify(
            {"success": False, "error": "Failed to delete user"}
        ), 400

@auth_bp.route("/api/users/<int:user_id>", methods=["PUT"])
@require_admin
def api_update_user(user_id):
    """Update user (admin only)."""
    db = current_app.config.get("DB")
    data = request.get_json()
    username = (
        data.get("username", "").strip() if data.get("username") else None
    )
    password = data.get("password", "") if data.get("password") else None
    is_admin = data.get("is_admin") if "is_admin" in data else None

    if password and len(password) < 6:
        return jsonify(
            {
                "success": False,
                "error": "Password must be at least 6 characters",
            }
        ), 400

    if not db:
        return jsonify(
            {"success": False, "error": "Authentication not available"}
        ), 500

    if db.update_user(user_id, username, password, is_admin):
        return jsonify(
            {"success": True, "message": "User updated successfully"}
        )
    else:
        return jsonify(
            {"success": False, "error": "Failed to update user"}
        ), 400

@auth_bp.route("/api/change-password", methods=["POST"])
@require_api_auth
def api_change_password():
    """Change user password."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return jsonify(
            {"success": False, "error": "Authentication not enabled"}
        ), 400

    session_token = request.cookies.get("session_token")
    user = db.get_user_by_session(session_token)
    if not user:
        return jsonify({"success": False, "error": "Invalid session"}), 401

    data = request.get_json()
    current_password = data.get("current_password", "")
    new_password = data.get("new_password", "")

    if not current_password or not new_password:
        return jsonify(
            {
                "success": False,
                "error": "Current and new passwords are required",
            }
        ), 400

    if len(new_password) < 6:
        return jsonify(
            {
                "success": False,
                "error": "New password must be at least 6 characters",
            }
        ), 400

    if db.change_password(user["id"], current_password, new_password):
        return jsonify(
            {"success": True, "message": "Password changed successfully"}
        )
    else:
        return jsonify(
            {"success": False, "error": "Failed to change password. Current password may be incorrect.",}
        ), 400