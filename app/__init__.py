"""
app/__init__.py — Application factory.

Using the factory pattern lets us create multiple app instances (e.g. for
testing) without running into circular-import or global-state issues.
"""
import os
from flask import Flask
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Module-level limiter; init_app() is called inside create_app().
# Default limits passed directly — Flask-Limiter 4.x reads RATELIMIT_DEFAULT_LIMITS
# from config, but passing here is more explicit and avoids config-key confusion.
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)


def create_app(config_class=None):
    from config import DevelopmentConfig

    if config_class is None:
        config_class = DevelopmentConfig

    app = Flask(
        __name__,
        # Templates live inside the app package; Flask finds them automatically.
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        # Static files live at project root/static/.
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
        static_url_path="/static",
    )
    app.config.from_object(config_class)

    # ── Production secret validation ──────────────────────────────────────────
    # Fail fast if SECRET_KEY / JWT_SECRET_KEY are not set in production, rather
    # than silently generating per-process random keys that break multi-worker
    # deployments (each worker signs with a different key).
    if hasattr(config_class, "_validate"):
        config_class._validate()

    # ── Ensure runtime directories exist ─────────────────────────────────────
    os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # ── Extensions ───────────────────────────────────────────────────────────
    limiter.init_app(app)

    # ── Database schema ───────────────────────────────────────────────────────
    from app.models import init_db

    with app.app_context():
        init_db(app)

    # ── Blueprints ────────────────────────────────────────────────────────────
    from app.auth.routes import auth_bp
    from app.main.routes import main_bp
    from app.admin.routes import admin_bp
    from app.uploads.routes import uploads_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(uploads_bp, url_prefix="/uploads")

    # ── Security headers on every response ───────────────────────────────────
    # OWASP A05: Apply security headers globally.
    from app.utils.security import apply_security_headers

    app.after_request(apply_security_headers)

    return app
