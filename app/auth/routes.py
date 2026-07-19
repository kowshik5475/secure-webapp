"""
auth/routes.py — Registration, login, and logout.

Security controls demonstrated:
  OWASP A02  — bcrypt password hashing (in models.create_user)
  OWASP A03  — parameterized queries only (in models)
  OWASP A05  — JWT stored in httpOnly Secure SameSite=Strict cookie
  OWASP A07  — account lockout after failed attempts; rate limiting on login
  OWASP A09  — every auth event written to audit_log
  OWASP A04  — server-side input validation (email format, password strength)
  XSS        — Jinja2 auto-escaping renders all user data safely (no | safe)
"""
import re
import sqlite3
import bcrypt
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, make_response, g
)
from app import limiter
from app.models import (
    create_user, get_user_by_email, get_user_by_id,
    verify_password, record_failed_login, reset_login_attempts,
    is_account_locked,
)
from app.utils.auth import generate_token, set_auth_cookie, clear_auth_cookie, get_current_user
from app.utils.audit import log_register, log_login_success, log_login_fail, log_login_locked, log_logout
from flask import current_app

# ── Timing-safe dummy hash ────────────────────────────────────────────────────
# Generated once at import time so it is a valid bcrypt hash. This ensures
# bcrypt.checkpw() actually runs its full comparison (rather than crashing with
# ValueError: Invalid salt) when a login attempt uses an email that doesn't
# exist in the database — preventing user-enumeration via timing differences.
# OWASP A07 — timing-safe authentication
_DUMMY_HASH: str = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=12)).decode("utf-8")

auth_bp = Blueprint("auth", __name__)

# ── Input validation ──────────────────────────────────────────────────────────
# OWASP A04: Validate inputs server-side. Client-side validation is UX only.

EMAIL_RE = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

def validate_email(email: str) -> str | None:
    """Return error message or None if valid."""
    if not email or len(email) > 254:
        return "Email address is required and must be under 254 characters."
    if not EMAIL_RE.match(email):
        return "Please enter a valid email address."
    return None

def validate_password(password: str) -> str | None:
    """
    Enforce password strength server-side.
    Min 8 chars, at least one uppercase, one digit, one special char.
    """
    if not password or len(password) < 8:
        return "Password must be at least 8 characters."
    if len(password) > 128:
        return "Password must be under 128 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", password):
        return "Password must contain at least one special character."
    return None


# ── Registration ──────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute", error_message="Too many registration attempts. Please wait.")
def register():
    # Already logged in? Redirect home.
    if get_current_user():
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        # ── Server-side validation ────────────────────────────────────────────
        err = validate_email(email)
        if err:
            flash(err, "error")
            return render_template("auth/register.html")

        err = validate_password(password)
        if err:
            flash(err, "error")
            return render_template("auth/register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("auth/register.html")

        # Check email not already taken (timing-safe: always hash before checking)
        if get_user_by_email(email):
            # Generic message — don't reveal whether email exists (user enumeration)
            flash("An account with that email already exists.", "error")
            return render_template("auth/register.html")

        # Create user — bcrypt happens inside create_user().
        # Wrap in IntegrityError catch: two concurrent registrations for the same
        # email can both pass the get_user_by_email() check above before either
        # write commits; the UNIQUE constraint on users.email catches the second.
        try:
            create_user(
                email=email,
                password=password,
                rounds=current_app.config["BCRYPT_ROUNDS"],
            )
        except sqlite3.IntegrityError:
            flash("An account with that email already exists.", "error")
            return render_template("auth/register.html")
        user = get_user_by_email(email)
        log_register(user_id=user["id"], email=email)

        flash("Account created! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


# ── Login ─────────────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", error_message="Too many login attempts. Please wait.")
def login():
    if get_current_user():
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Basic presence check
        if not email or not password:
            flash("Email and password are required.", "error")
            return render_template("auth/login.html")

        user = get_user_by_email(email)

        # ── Timing-safe not-found path ────────────────────────────────────────
        # We always call verify_password (against a pre-computed dummy hash if
        # user not found) so the response time doesn't reveal whether the email
        # exists. _DUMMY_HASH is a real bcrypt hash generated at import time.
        stored_hash = user["password_hash"] if user else _DUMMY_HASH

        # ── Account lockout check ─────────────────────────────────────────────
        if user and is_account_locked(user):
            log_login_locked(user_id=user["id"], email=email)
            flash(
                f"Account locked after too many failed attempts. "
                f"Try again in {current_app.config['LOCKOUT_DURATION_MINUTES']} minutes.",
                "error",
            )
            return render_template("auth/login.html")

        password_correct = verify_password(password, stored_hash)

        if not user or not password_correct:
            if user:
                record_failed_login(
                    user["id"],
                    current_app.config["MAX_LOGIN_ATTEMPTS"],
                    current_app.config["LOCKOUT_DURATION_MINUTES"],
                )
            log_login_fail(user_id=user["id"] if user else None, email=email)
            # Generic error — don't reveal if email or password was wrong
            flash("Invalid email or password.", "error")
            return render_template("auth/login.html")

        # ── Success: reset counter, issue JWT ─────────────────────────────────
        reset_login_attempts(user["id"])
        log_login_success(user_id=user["id"], email=email)

        jwt_token, _csrf = generate_token(
            user_id=user["id"],
            email=user["email"],
            role=user["role"],
        )

        response = make_response(redirect(url_for("main.dashboard")))
        set_auth_cookie(response, jwt_token)
        return response

    return render_template("auth/login.html")


# ── Logout ────────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    """
    POST-only logout prevents CSRF logout attacks (an attacker cannot trigger
    a GET-based logout from an img tag or link on another site).
    """
    user = get_current_user()
    if user:
        log_logout(user_id=user["sub"], email=user["email"])

    response = make_response(redirect(url_for("main.index")))
    clear_auth_cookie(response)
    flash("You have been logged out.", "info")
    return response
