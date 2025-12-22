import logging
from flask import Blueprint, render_template, jsonify, request, session, redirect, url_for, current_app
from authlib.integrations.flask_client import OAuthError
from ..utils import require_api_auth, require_admin, require_auth 

auth_bp = Blueprint('auth', __name__, url_prefix='/')

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Login page route."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    oidc_enabled = current_app.config.get("OIDC_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    if oidc_enabled:
        # If OIDC is enabled, redirect to OIDC login
        return redirect(url_for("auth.oidc_login"))

    if not db.has_local_users(): # Check for local users specifically
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
                secure=False, # Set to True in production with HTTPS
                max_age=30 * 24 * 60 * 60,
            )
            return response
        else:
            return jsonify(
                {"success": False, "error": "Invalid credentials"}
            ), 401

    return render_template("login.html", oidc_enabled=oidc_enabled)

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Logout route."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    oidc_enabled = current_app.config.get("OIDC_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    session_token = request.cookies.get("session_token")
    if session_token:
        db.delete_session(session_token)

    response = jsonify({"success": True, "redirect": url_for("auth.login")})
    response.set_cookie("session_token", "", expires=0)

    if oidc_enabled:
        # If OIDC is enabled, also redirect to OIDC provider's logout endpoint if available
        # This assumes the OIDC provider has a logout endpoint and Authlib handles it.
        # For simplicity, we'll just redirect to local login after clearing session.
        # A full OIDC logout would involve redirecting to the OIDC provider's end_session_endpoint.
        pass # For now, just clear local session and redirect to login

    return response

@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    """First-time setup route for creating admin user."""
    auth_enabled = current_app.config.get("AUTH_ENABLED", False)
    oidc_enabled = current_app.config.get("OIDC_ENABLED", False)
    db = current_app.config.get("DB")

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    if oidc_enabled:
        # If OIDC is enabled, local setup is not allowed
        return redirect(url_for("auth.login"))

    if db.has_local_users(): # Check for local users specifically
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
    oidc_enabled = current_app.config.get("OIDC_ENABLED", False)

    if not auth_enabled or not db:
        return redirect(url_for("main.index"))

    session_token = request.cookies.get("session_token")
    user = db.get_user_by_session(session_token)
    users = db.get_all_users() if user and user["is_admin"] else []

    return render_template("settings.html", user=user, users=users, oidc_enabled=oidc_enabled)

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
    """Create new local user (admin only)."""
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

    # Ensure we are creating a local user, not an OIDC user
    new_user = db.create_user(username, password, is_admin, oidc_id=None, oidc_groups=None)
    if new_user:
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

    # Get user info to check if it's the original admin or an OIDC user
    users = db.get_all_users()
    user_to_delete = next((u for u in users if u["id"] == user_id), None)

    if user_to_delete and (user_to_delete.get("is_original_admin") or user_to_delete.get("oidc_id")):
        return jsonify(
            {"success": False, "error": "Cannot delete original admin or OIDC-managed users"}
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

    # Get user info to check if it's an OIDC user
    user_to_update = db.get_user_by_session(request.cookies.get("session_token")) # Get current user
    if user_to_update and user_to_update["id"] == user_id: # If updating self
        pass # Allow updating own password/username
    else: # If updating another user
        target_user = db.get_user_by_session(request.cookies.get("session_token")) # This is wrong, need to get target user by ID
        all_users = db.get_all_users()
        target_user = next((u for u in all_users if u["id"] == user_id), None)

        if target_user and target_user.get("oidc_id"):
            return jsonify(
                {"success": False, "error": "Cannot update OIDC-managed user details (username/password/admin status). Groups are managed by OIDC provider."}
            ), 400

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

    if user.get("oidc_id"):
        return jsonify({"success": False, "error": "OIDC users cannot change password locally."}), 400

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

# OIDC Routes
@auth_bp.route("/oidc-login")
def oidc_login():
    """Initiate OIDC login flow."""
    if not current_app.config.get("OIDC_ENABLED"):
        return redirect(url_for("auth.login"))

    oauth = current_app.config["OAUTH"]
    redirect_uri = url_for('auth.oidc_callback', _external=True)
    return oauth.aniworld_oidc.authorize_redirect(redirect_uri)

@auth_bp.route("/oidc-callback")
def oidc_callback():
    """Handle OIDC callback and process user information."""
    if not current_app.config.get("OIDC_ENABLED"):
        return redirect(url_for("auth.login"))

    oauth = current_app.config["OAUTH"]
    db = current_app.config["DB"]
    oidc_admin_group = current_app.config["OIDC_ADMIN_GROUP"]
    oidc_username_claim = current_app.config["OIDC_USERNAME_CLAIM"]
    oidc_groups_claim = current_app.config["OIDC_GROUPS_CLAIM"]

    try:
        token = oauth.aniworld_oidc.authorize_access_token()
        userinfo = oauth.aniworld_oidc.parse_id_token(token)

        oidc_id = userinfo.get('sub')
        username = userinfo.get(oidc_username_claim, oidc_id) # Fallback to sub if username claim not found
        oidc_groups = userinfo.get(oidc_groups_claim, [])

        if not isinstance(oidc_groups, list): # Handle cases where groups might be a string or other format
            if isinstance(oidc_groups, str):
                oidc_groups = [g.strip() for g in oidc_groups.split(',')]
            else:
                oidc_groups = []

        is_admin = oidc_admin_group in oidc_groups

        user = db.get_user_by_oidc_id(oidc_id)

        if user:
            # User exists, update groups and admin status if changed
            if user["oidc_groups"] != oidc_groups or user["is_admin"] != is_admin:
                db.update_user(user["id"], is_admin=is_admin, oidc_groups=oidc_groups)
                logging.info(f"Updated OIDC user {username} (ID: {user['id']}) with new groups/admin status.")
            user_id = user["id"]
        else:
            # New user, create account
            new_user = db.create_user(
                username=username,
                password=None, # No local password for OIDC users
                is_admin=is_admin,
                is_original_admin=False, # OIDC users are not original admins
                oidc_id=oidc_id,
                oidc_groups=oidc_groups,
            )
            if not new_user:
                logging.error(f"Failed to create OIDC user {username} with ID {oidc_id}")
                return jsonify({"success": False, "error": "Failed to create user account"}), 500
            user_id = new_user["id"]
            logging.info(f"Created new OIDC user {username} (ID: {user_id}) with groups: {oidc_groups}")

        # Create local session for the user
        session_token = db.create_session(user_id)
        response = redirect(url_for("main.index"))
        response.set_cookie(
            "session_token",
            session_token,
            httponly=True,
            secure=False, # Set to True in production with HTTPS
            max_age=30 * 24 * 60 * 60,
        )
        return response

    except OAuthError as e:
        logging.error(f"OIDC OAuthError: {e}")
        return jsonify({"success": False, "error": f"OIDC login failed: {e.error}"}), 400
    except Exception as e:
        logging.error(f"OIDC callback error: {e}")
        return jsonify({"success": False, "error": "OIDC login failed due to an unexpected error"}), 500