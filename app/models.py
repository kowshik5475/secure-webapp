"""
models.py — Database access layer using raw SQLite with parameterized queries.

OWASP A03 — SQL Injection Prevention:
  Every query uses ? placeholders. String-concatenated SQL is never used.
  SQLite's parameterized API guarantees the values are treated as data,
  not executable SQL.

OWASP A02 — Cryptographic Failures:
  Passwords are hashed with bcrypt (never stored plaintext).
  bcrypt is adaptive: the work factor can be increased as hardware improves.
"""
import sqlite3
import datetime
import bcrypt
from contextlib import contextmanager
from flask import current_app


# ── Connection helper ─────────────────────────────────────────────────────────

def _db_path():
    """Return the configured database path."""
    return current_app.config["DATABASE_PATH"]


def _db_path_from_app(app):
    return app.config["DATABASE_PATH"]


@contextmanager
def get_db(app=None):
    """
    Context manager that yields a sqlite3 connection.
    Commits on clean exit, rolls back on exception, always closes.
    row_factory=sqlite3.Row lets callers access columns by name.
    """
    path = _db_path_from_app(app) if app else _db_path()
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # Concurrent readers
    conn.execute("PRAGMA foreign_keys=ON")   # Enforce FK constraints
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── Schema ────────────────────────────────────────────────────────────────────

def init_db(app):
    """
    Create tables if they don't exist.
    Uses only DDL with literal table/column names — no user input reaches here.
    """
    with get_db(app) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                email           TEXT    UNIQUE NOT NULL,
                password_hash   TEXT    NOT NULL,
                role            TEXT    NOT NULL DEFAULT 'user',
                is_locked       INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until    TEXT,
                created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
                updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
            );

            CREATE TABLE IF NOT EXISTS uploaded_files (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id       INTEGER NOT NULL,
                original_name TEXT    NOT NULL,
                stored_name   TEXT    NOT NULL,
                mime_type     TEXT    NOT NULL,
                size_bytes    INTEGER NOT NULL,
                uploaded_at   TEXT    NOT NULL DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL DEFAULT (datetime('now')),
                event_type  TEXT    NOT NULL,
                user_id     INTEGER,
                actor_id    INTEGER,
                ip_address  TEXT,
                details     TEXT
            );
        """)


# ── User operations ───────────────────────────────────────────────────────────

def create_user(email: str, password: str, role: str = "user", rounds: int = 12):
    """
    Hash password with bcrypt then insert user.
    OWASP A02: bcrypt is a slow, salted hash — resistant to brute-force and
    rainbow-table attacks. The salt is embedded in the hash string itself.
    """
    pw_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=rounds),
    ).decode("utf-8")

    with get_db() as conn:
        # OWASP A03: Parameterized — email is data, not SQL.
        conn.execute(
            "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
            (email.lower().strip(), pw_hash, role),
        )


def get_user_by_email(email: str):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE email = ?",
            (email.lower().strip(),),
        ).fetchone()


def get_user_by_id(user_id: int):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()


def get_all_users():
    with get_db() as conn:
        return conn.execute(
            """SELECT id, email, role, is_locked, failed_attempts,
                      locked_until, created_at
               FROM users
               ORDER BY created_at DESC"""
        ).fetchall()


def update_user_role(user_id: int, new_role: str):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET role = ?, updated_at = datetime('now') WHERE id = ?",
            (new_role, user_id),
        )


def verify_password(plain: str, hashed: str) -> bool:
    """
    bcrypt.checkpw is constant-time — prevents timing-based user enumeration.
    """
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ── Account lockout ───────────────────────────────────────────────────────────

def record_failed_login(user_id: int, max_attempts: int, lockout_minutes: int):
    """
    OWASP A07: Increment fail counter; lock when threshold reached.
    """
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = failed_attempts + 1, updated_at = datetime('now') WHERE id = ?",
            (user_id,),
        )
        row = conn.execute(
            "SELECT failed_attempts FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        if row and row["failed_attempts"] >= max_attempts:
            locked_until = (
                datetime.datetime.utcnow()
                + datetime.timedelta(minutes=lockout_minutes)
            ).isoformat()
            conn.execute(
                "UPDATE users SET is_locked = 1, locked_until = ?, updated_at = datetime('now') WHERE id = ?",
                (locked_until, user_id),
            )


def reset_login_attempts(user_id: int):
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET failed_attempts = 0, is_locked = 0, locked_until = NULL, updated_at = datetime('now') WHERE id = ?",
            (user_id,),
        )


def is_account_locked(user) -> bool:
    """Auto-unlock after the lockout window expires."""
    if not user["is_locked"]:
        return False
    if user["locked_until"]:
        locked_until = datetime.datetime.fromisoformat(user["locked_until"])
        if datetime.datetime.utcnow() > locked_until:
            reset_login_attempts(user["id"])
            return False
    return True


# ── File records ──────────────────────────────────────────────────────────────

def store_uploaded_file(user_id: int, original_name: str, stored_name: str,
                        mime_type: str, size_bytes: int):
    with get_db() as conn:
        conn.execute(
            """INSERT INTO uploaded_files
               (user_id, original_name, stored_name, mime_type, size_bytes)
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, original_name, stored_name, mime_type, size_bytes),
        )


def get_user_files(user_id: int):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM uploaded_files WHERE user_id = ? ORDER BY uploaded_at DESC",
            (user_id,),
        ).fetchall()


# ── Audit log ─────────────────────────────────────────────────────────────────

def write_audit_log(event_type: str, user_id=None, actor_id=None,
                    ip_address=None, details=None):
    """
    OWASP A09: Security logging. Every sensitive event is recorded with
    timestamp, actor, target, and IP so incidents can be reconstructed.
    """
    with get_db() as conn:
        conn.execute(
            """INSERT INTO audit_log (event_type, user_id, actor_id, ip_address, details)
               VALUES (?, ?, ?, ?, ?)""",
            (event_type, user_id, actor_id, ip_address, details),
        )


def get_recent_audit_log(limit: int = 100):
    with get_db() as conn:
        return conn.execute(
            """SELECT al.*, u.email as user_email, a.email as actor_email
               FROM audit_log al
               LEFT JOIN users u ON al.user_id = u.id
               LEFT JOIN users a ON al.actor_id = a.id
               ORDER BY al.timestamp DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
