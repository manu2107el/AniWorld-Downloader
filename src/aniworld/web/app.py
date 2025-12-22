"""
Flask web application for AniWorld Downloader
"""

import logging
import os
import time
import threading
import webbrowser
from flask import Flask, Blueprint, render_template, jsonify, request, session, redirect, url_for
from authlib.integrations.flask_client import OAuth

# Import modules from the parent package
from .. import config
from .database import UserDatabase
from .download_manager import get_download_manager
from .routes.auth import auth_bp
from .routes.main import main_bp
from .routes.api import api_bp


class WebApp:
    """Flask web application wrapper for AniWorld Downloader"""

    def __init__(self, host="127.0.0.1", port=5000, debug=False, arguments=None):
        """
        Initialize the Flask web application.

        Args:
            host: Host to bind to (default: 127.0.0.1)
            port: Port to bind to (default: 5000)
            debug: Enable Flask debug mode (default: False)
            arguments: Command line arguments object
        """
        self.host = host
        self.port = port
        self.debug = debug
        self.arguments = arguments
        self.start_time = time.time()

        # Authentication settings
        self.auth_enabled = (
            getattr(arguments, "enable_web_auth", False) if arguments else False
        )
        self.db = UserDatabase() if self.auth_enabled else None

        # Download manager
        self.download_manager = get_download_manager(self.db)

        # Create Flask app
        self.app = self._create_app()

    def _create_app(self) -> Flask:
        """Create and configure Flask application."""
        # Get the web module directory
        web_dir = os.path.dirname(os.path.abspath(__file__))

        app = Flask(
            __name__,
            template_folder=os.path.join(web_dir, "templates"),
            static_folder=os.path.join(web_dir, "static"),
        )

        # Configure Flask
        app.config["SECRET_KEY"] = os.urandom(24)
        app.config["JSON_SORT_KEYS"] = False
        app.config["AUTH_ENABLED"] = self.auth_enabled
        app.config["DB"] = self.db
        app.config["DOWNLOAD_MANAGER"] = self.download_manager
        app.config["ARGUMENTS"] = self.arguments # Pass arguments for download path etc.
        app.config["CONFIG"] = config # Pass the entire config module
        app.config["START_TIME"] = self.start_time

        # OIDC Configuration
        app.config["OIDC_ENABLED"] = config.OIDC_ENABLED
        if config.OIDC_ENABLED:
           
            app.config["OIDC_CLIENT_ID"] = config.OIDC_CLIENT_ID
            app.config["OIDC_CLIENT_SECRET"] = config.OIDC_CLIENT_SECRET
            app.config["OIDC_DISCOVERY_URL"] = config.OIDC_DISCOVERY_URL
            app.config["OIDC_ADMIN_GROUP"] = config.OIDC_ADMIN_GROUP
            app.config["OIDC_USERNAME_CLAIM"] = config.OIDC_USERNAME_CLAIM
            app.config["OIDC_GROUPS_CLAIM"] = config.OIDC_GROUPS_CLAIM

            # Initialize Authlib OAuth client
            oauth = OAuth(app)
            oauth.register(
                name='aniworld_oidc',
                client_id=app.config["OIDC_CLIENT_ID"],
                client_secret=app.config["OIDC_CLIENT_SECRET"],
                server_metadata_url=app.config["OIDC_DISCOVERY_URL"],
                client_kwargs={'scope': 'openid email profile groups'}, # Request standard claims + groups
            )
            app.config["OAUTH"] = oauth # Store oauth object in app config

        # Register blueprints
        app.register_blueprint(auth_bp)
        app.register_blueprint(main_bp)
        app.register_blueprint(api_bp)

        return app

    def run(self):
        """Run the Flask web application."""
        logging.info("Starting AniWorld Downloader Web Interface...")
        logging.info(f"Server running at http://{self.host}:{self.port}")

        try:
            self.app.run(
                host=self.host,
                port=self.port,
                debug=self.debug,
                use_reloader=False,  # Disable reloader to avoid conflicts
            )
        except KeyboardInterrupt:
            logging.info("Web interface stopped by user")
        except Exception as err:
            logging.error(f"Error running web interface: {err}")
            raise


def create_app(host="127.0.0.1", port=5000, debug=False, arguments=None) -> WebApp:
    """
    Factory function to create web application.

    Args:
        host: Host to bind to
        port: Port to bind to
        debug: Enable debug mode
        arguments: Command line arguments object

    Returns:
        WebApp instance
    """
    return WebApp(host=host, port=port, debug=debug, arguments=arguments)


def start_web_interface(arguments=None, port=5000, debug=False):
    """Start the web interface with configurable settings."""
    # Determine host based on web_expose argument
    host = "0.0.0.0" if getattr(arguments, "web_expose", False) else "127.0.0.1"
    web_app = create_app(host=host, port=port, debug=debug, arguments=arguments)

    # Print startup status
    auth_status = (
        "Authentication ENABLED"
        if getattr(arguments, "enable_web_auth", False)
        else "No Authentication (Local Mode)"
    )
    browser_status = (
        "Browser will open automatically"
        if not getattr(arguments, "no_browser", False)
        else "Browser auto-open disabled"
    )
    expose_status = (
        "ENABLED (0.0.0.0)"
        if getattr(arguments, "web_expose", False)
        else "DISABLED (localhost only)"
    )

    # Get download path
    download_path = str(config.DEFAULT_DOWNLOAD_PATH)
    if (
        arguments
        and hasattr(arguments, "output_dir")
        and arguments.output_dir is not None
    ):
        download_path = str(arguments.output_dir)

    # Show appropriate server address based on host
    server_address = (
        f"http://{host}:{port}" if host == "0.0.0.0" else f"http://localhost:{port}"
    )

    print("\n" + "=" * 69)
    print("🌐 AniWorld Downloader Web Interface")
    print("=" * 69)
    print(f"📍 Server Address:   {server_address}")
    print(f"🔐 Security Mode:    {auth_status}")
    if config.OIDC_ENABLED:
        print(f"🔑 OIDC Enabled:     YES (Provider: {config.OIDC_DISCOVERY_URL.split('/.well-known')[0]})")
        print(f"👥 Admin Group:      '{config.OIDC_ADMIN_GROUP}'")
    print(f"🌐 External Access:  {expose_status}")
    print(f"📁 Download Path:    {download_path}")
    print(f"🐞 Debug Mode:       {'ENABLED' if debug else 'DISABLED'}")
    print(f"📦 Version:          {config.VERSION}")
    print(f"🌏 Browser:          {browser_status}")
    print("=" * 69)
    print("💡 Access the web interface by opening the URL above in your browser")
    if getattr(arguments, "enable_web_auth", False) and not config.OIDC_ENABLED:
        print("💡 First visit will prompt you to create an admin account")
    elif config.OIDC_ENABLED:
        print("💡 Use the 'Login with OIDC' button to authenticate.")
        print(f"💡 Users in the OIDC group '{config.OIDC_ADMIN_GROUP}' will be granted admin privileges.")
    print("💡 Press Ctrl+C to stop the server")
    print("=" * 69 + "\n")

    # Open browser automatically unless disabled
    if not getattr(arguments, "no_browser", False):

        def open_browser():
            time.sleep(1.5)
            url = f"http://localhost:{port}"
            logging.info(f"Opening browser at {url}")
            try:
                webbrowser.open(url)
            except Exception as e:
                logging.warning(f"Could not open browser automatically: {e}")

        browser_thread = threading.Thread(target=open_browser)
        browser_thread.daemon = True
        browser_thread.start()