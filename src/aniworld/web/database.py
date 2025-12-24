"""
Database models and utilities for AniWorld Downloader web authentication
"""

import hashlib
import os
import secrets
import sqlite3
import json
from typing import Optional, Dict, List
from pathlib import Path


def get_database_path() -> str:
    """Get the persistent database path based on OS"""
    if os.path.exists("/.dockerenv"):  # 2. Docker environment
        db_dir = "/app/data"
    elif os.name == "nt":  # 2. Windows
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        db_dir = os.path.join(appdata, "aniworld")
    else:  # 3. Linux and others
        db_dir = os.path.expanduser("~/.local/share/aniworld")

    # Ensure directory exists
    Path(db_dir).mkdir(parents=True, exist_ok=True)
    return os.path.join(db_dir, "aniworld.db")


class UserDatabase:
    """SQLite database manager for user authentication"""

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the user database.

        Args:
            db_path: Path to the SQLite database file (if None, uses system location)
        """
        self.db_path = db_path or get_database_path()
        self._init_database()

    def _init_database(self) -> None:
        """Initialize the database tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT, -- Nullable for OIDC users
                    salt TEXT,          -- Nullable for OIDC users
                    is_admin BOOLEAN NOT NULL DEFAULT 0,
                    is_original_admin BOOLEAN NOT NULL DEFAULT 0,
                    oidc_id TEXT UNIQUE, -- Unique identifier from OIDC provider
                    oidc_groups TEXT,    -- JSON string of groups from OIDC provider
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)

            # Create sessions table for session management
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_token TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            """)

            conn.commit()

    def _hash_password(self, password: str, salt: str) -> str:
        """
        Hash a password with salt using SHA-256.

        Args:
            password: Plain text password
            salt: Salt string

        Returns:
            Hashed password
        """
        return hashlib.sha256((password + salt).encode()).hexdigest()

    def create_user(
        self,
        username: str,
        password: Optional[str] = None,
        is_admin: bool = False,
        is_original_admin: bool = False,
        oidc_id: Optional[str] = None,
        oidc_groups: Optional[List[str]] = None,
    ) -> Optional[Dict]:
        """
        Create a new user.

        Args:
            username: Username
            password: Plain text password (optional, for local users)
            is_admin: Whether user should have admin privileges
            is_original_admin: Whether this is the original admin user
            oidc_id: Unique identifier from OIDC provider (optional, for OIDC users)
            oidc_groups: List of groups from OIDC provider (optional, for OIDC users)

        Returns:
            User dictionary if user was created successfully, None otherwise
        """
        try:
            salt = None
            password_hash = None
            if password:
                salt = secrets.token_hex(16)
                password_hash = self._hash_password(password, salt)

            oidc_groups_json = json.dumps(oidc_groups) if oidc_groups else None

            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, salt, is_admin, is_original_admin, oidc_id, oidc_groups)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (username, password_hash, salt, is_admin, is_original_admin, oidc_id, oidc_groups_json),
                )
                conn.commit()
                user_id = cursor.lastrowid
                return {
                    "id": user_id,
                    "username": username,
                    "is_admin": is_admin,
                    "is_original_admin": is_original_admin,
                    "oidc_id": oidc_id,
                    "oidc_groups": oidc_groups,
                }

        except sqlite3.IntegrityError:
            # Username or oidc_id already exists
            return None
        except Exception as e:
            logging.error(f"Error creating user: {e}")
            return None

    def verify_user(self, username: str, password: str) -> Optional[Dict]:
        """
        Verify user credentials for local users.

        Args:
            username: Username
            password: Plain text password

        Returns:
            User dictionary if credentials are valid, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, username, password_hash, salt, is_admin, is_original_admin, oidc_id, oidc_groups
                    FROM users WHERE username = ? AND oidc_id IS NULL
                """, # Only verify local users
                    (username,),
                )

                row = cursor.fetchone()
                if not row:
                    return None

                user_id, username, stored_hash, salt, is_admin, is_original_admin, oidc_id, oidc_groups_json = row

                # Verify password
                if self._hash_password(password, salt) == stored_hash:
                    # Update last login
                    cursor.execute(
                        """
                        UPDATE users SET last_login = CURRENT_TIMESTAMP
                        WHERE id = ?
                    """,
                        (user_id,),
                    )
                    conn.commit()

                    return {
                        "id": user_id,
                        "username": username,
                        "is_admin": bool(is_admin),
                        "is_original_admin": bool(is_original_admin),
                        "oidc_id": oidc_id,
                        "oidc_groups": json.loads(oidc_groups_json) if oidc_groups_json else [],
                    }

                return None

        except Exception as e:
            logging.error(f"Error verifying user: {e}")
            return None

    def create_session(self, user_id: int) -> str:
        """
        Create a new session for a user.

        Args:
            user_id: User ID

        Returns:
            Session token
        """
        session_token = secrets.token_urlsafe(32)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Clean up expired sessions first
            cursor.execute("""
                DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP
            """)

            # Create new session (expires in 30 days)
            cursor.execute(
                """
                INSERT INTO sessions (session_token, user_id, expires_at)
                VALUES (?, ?, datetime('now', '+30 days'))
            """,
                (session_token, user_id),
            )

            conn.commit()

        return session_token

    def get_user_by_session(self, session_token: str) -> Optional[Dict]:
        """
        Get user information by session token.

        Args:
            session_token: Session token

        Returns:
            User dictionary if session is valid, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT u.id, u.username, u.is_admin, u.is_original_admin, u.oidc_id, u.oidc_groups
                    FROM users u
                    JOIN sessions s ON u.id = s.user_id
                    WHERE s.session_token = ? AND s.expires_at > CURRENT_TIMESTAMP
                """,
                    (session_token,),
                )

                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "username": row[1],
                        "is_admin": bool(row[2]),
                        "is_original_admin": bool(row[3]),
                        "oidc_id": row[4],
                        "oidc_groups": json.loads(row[5]) if row[5] else [],
                    }

                return None

        except Exception as e:
            logging.error(f"Error getting user by session: {e}")
            return None

    def get_user_by_oidc_id(self, oidc_id: str) -> Optional[Dict]:
        """
        Get user information by OIDC ID.

        Args:
            oidc_id: Unique identifier from OIDC provider

        Returns:
            User dictionary if user exists, None otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, username, is_admin, is_original_admin, oidc_id, oidc_groups
                    FROM users WHERE oidc_id = ?
                """,
                    (oidc_id,),
                )
                row = cursor.fetchone()
                if row:
                    return {
                        "id": row[0],
                        "username": row[1],
                        "is_admin": bool(row[2]),
                        "is_original_admin": bool(row[3]),
                        "oidc_id": row[4],
                        "oidc_groups": json.loads(row[5]) if row[5] else [],
                    }
                return None
        except Exception as e:
            logging.error(f"Error getting user by OIDC ID: {e}")
            return None

    def delete_session(self, session_token: str) -> bool:
        """
        Delete a session (logout).

        Args:
            session_token: Session token to delete

        Returns:
            True if session was deleted, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM sessions WHERE session_token = ?
                """,
                    (session_token,),
                )
                conn.commit()
                return cursor.rowcount > 0

        except Exception as e:
            logging.error(f"Error deleting session: {e}")
            return False

    def get_all_users(self) -> List[Dict]:
        """
        Get all users (admin only).

        Returns:
            List of user dictionaries
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT id, username, is_admin, is_original_admin, oidc_id, oidc_groups, created_at, last_login
                    FROM users ORDER BY username
                """)

                users = []
                for row in cursor.fetchall():
                    users.append(
                        {
                            "id": row[0],
                            "username": row[1],
                            "is_admin": bool(row[2]),
                            "is_original_admin": bool(row[3]),
                            "oidc_id": row[4],
                            "oidc_groups": json.loads(row[5]) if row[5] else [],
                            "created_at": row[6],
                            "last_login": row[7],
                        }
                    )

                return users

        except Exception as e:
            logging.error(f"Error getting all users: {e}")
            return []

    def delete_user(self, user_id: int) -> bool:
        """
        Delete a user.

        Args:
            user_id: User ID to delete

        Returns:
            True if user was deleted, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.commit()
                return cursor.rowcount > 0

        except Exception as e:
            logging.error(f"Error deleting user: {e}")
            return False

    def update_user(
        self,
        user_id: int,
        username: str = None,
        password: str = None,
        is_admin: bool = None,
        oidc_groups: Optional[List[str]] = None,
    ) -> bool:
        """
        Update user information.

        Args:
            user_id: User ID to update
            username: New username (optional)
            password: New password (optional)
            is_admin: New admin status (optional)
            oidc_groups: New OIDC groups (optional, for OIDC users)

        Returns:
            True if user was updated, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                updates = []
                params = []

                if username is not None:
                    updates.append("username = ?")
                    params.append(username)

                if password is not None:
                    salt = secrets.token_hex(16)
                    password_hash = self._hash_password(password, salt)
                    updates.append("password_hash = ?")
                    updates.append("salt = ?")
                    params.extend([password_hash, salt])

                if is_admin is not None:
                    updates.append("is_admin = ?")
                    params.append(is_admin)

                if oidc_groups is not None:
                    updates.append("oidc_groups = ?")
                    params.append(json.dumps(oidc_groups))

                if not updates:
                    return True  # Nothing to update

                params.append(user_id)

                cursor.execute(
                    f"""
                    UPDATE users SET {", ".join(updates)}
                    WHERE id = ?
                """,
                    params,
                )

                conn.commit()
                return cursor.rowcount > 0

        except sqlite3.IntegrityError:
            # Username already exists
            return False
        except Exception as e:
            logging.error(f"Error updating user: {e}")
            return False

    def has_users(self) -> bool:
        """
        Check if any users exist in the database.

        Returns:
            True if at least one user exists, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                count = cursor.fetchone()[0]
                return count > 0

        except Exception as e:
            logging.error(f"Error checking for users: {e}")
            return False

    def has_local_users(self) -> bool:
        """
        Check if any local users (not OIDC) exist in the database.

        Returns:
            True if at least one local user exists, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users WHERE oidc_id IS NULL")
                count = cursor.fetchone()[0]
                return count > 0
        except Exception as e:
            logging.error(f"Error checking for local users: {e}")
            return False

    def change_password(
        self, user_id: int, current_password: str, new_password: str
    ) -> bool:
        """
        Change a local user's password.

        Args:
            user_id: User ID
            current_password: Current password for verification
            new_password: New password

        Returns:
            True if password was changed successfully, False otherwise
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # Get current password hash and salt for local user
                cursor.execute(
                    """
                    SELECT password_hash, salt FROM users WHERE id = ? AND oidc_id IS NULL
                """,
                    (user_id,),
                )

                row = cursor.fetchone()
                if not row:
                    return False # User not found or is an OIDC user

                stored_hash, salt = row

                # Verify current password
                if self._hash_password(current_password, salt) != stored_hash:
                    return False

                # Generate new salt and hash for new password
                new_salt = secrets.token_hex(16)
                new_hash = self._hash_password(new_password, new_salt)

                # Update password
                cursor.execute(
                    """
                    UPDATE users SET password_hash = ?, salt = ?
                    WHERE id = ?
                """,
                    (new_hash, new_salt, user_id),
                )

                conn.commit()
                return cursor.rowcount > 0

        except Exception as e:
            logging.error(f"Error changing password: {e}")
            return False

    def cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP
                """)
                conn.commit()

        except Exception as e:
            logging.error(f"Error cleaning up expired sessions: {e}")