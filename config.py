"""
config.py — Application configuration.

Security note: SECRET_KEY and JWT_SECRET_KEY are loaded from environment
variables in production. The fallbacks here are fine for dev (generated fresh
each restart), but production MUST set these via env vars so they survive
restarts and are not embedded in source code.
"""
import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # ── Cryptographic keys ───────────────────────────────────────────────────
    # OWASP A02 / A07: Use env vars in production; never hardcode secrets.
    SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_hex(32))
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", secrets.token_hex(32))

    # ── JWT ──────────────────────────────────────────────────────────────────
    JWT_EXPIRY_HOURS = 1  # Short-lived tokens reduce exposure window

    # ── Database (SQLite) ────────────────────────────────────────────────────
    # Stored in instance/ which is outside static/templates (not web-served).
    DATABASE_PATH = os.path.join(BASE_DIR, "instance", "app.db")

    # ── File uploads ─────────────────────────────────────────────────────────
    # OWASP A01 / A04: Store uploads OUTSIDE the web root; randomise names.
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    # Hard 5 MB limit enforced by Flask (MAX_CONTENT_LENGTH).
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024

    # Validated by magic bytes (filetype library), NOT file extension.
    ALLOWED_MIME_TYPES = {
        "image/png",
        "image/jpeg",
        "image/gif",
        "application/pdf",
    }

    # ── Password hashing ─────────────────────────────────────────────────────
    # OWASP recommends bcrypt work-factor ≥ 10; 12 is a safe modern default.
    BCRYPT_ROUNDS = 12

    # ── Account lockout ──────────────────────────────────────────────────────
    # OWASP A07: Lock account after N consecutive failures.
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 15

    # ── Rate limiting storage backend (default: in-memory) ───────────────────
    RATELIMIT_STORAGE_URI = "memory://"


class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    DEBUG = False
    BCRYPT_ROUNDS = 14  # Higher cost in production

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

    @classmethod
    def _validate(cls):
        """
        Raise at startup if required secrets are missing.

        In a multi-worker deployment (e.g. gunicorn -w 4) each worker process
        would generate its own secrets.token_hex(32) fallback, causing JWTs and
        flash cookies signed by one worker to be rejected by all others.
        Failing fast here forces the operator to set the env vars explicitly.
        """
        missing = [
            var for var in ("SECRET_KEY", "JWT_SECRET_KEY")
            if not os.environ.get(var)
        ]
        if missing:
            raise RuntimeError(
                f"ProductionConfig requires these environment variables to be set: "
                f"{', '.join(missing)}. "
                "Generate them with: python -c \"import secrets; print(secrets.token_hex(32))\""
            )
