"""
utils/auth.py — JWT management, CSRF synchronizer tokens, and route decorators.

OWASP A02 — Cryptographic Failures:
  JWTs are signed with HS256 using a strong secret key loaded from env.
  Tokens are short-lived (1 hour) to limit exposure.

OWASP A01 — Broken Access Control:
  login_required / admin_required decorators enforce auth server-side on
  every protected route. Client-side checks are UX only, not security.

OWASP A05 — Security Misconfiguration:
  JWT is stored in an httpOnly, Secure, SameSite=Strict cookie.
  httpOnly  → JavaScript cannot read it (blocks XSS token theft).
  Secure    → Only sent over HTTPS.
  SameSite=Strict → Browser won't attach it on cross-site requests (CSRF defence layer 1).

CSRF Synchronizer Token Pattern (layer 2):
  Every state-changing request (POST/PUT/DELETE) must include a CSRF token
  that was embedded in the rendered form. The token is stored in the JWT
  payload so it cannot be forged without the JWT secret.
"""
import secrets
import datetime
from functools import wraps

import jwt
from flask import current_app, request, jsonify, redirect, url_for, flash, g


# ── JWT helpers ───────────────────────────────────────────────────────────────

def generate_token(user_id: int, email: str, role: str) -> tuple[str, str]:
    """
    Build a JWT payload with:
      - Standard claims: sub, iat, exp
      - Custom claims:   role, csrf_token
    Returns (jwt_string, csrf_token).
    The csrf_token is embedded in the JWT so it cannot be tampered with
    independently, and is also placed in every form as a hidden field.
    """
    csrf_token = secrets.token_hex(32)
    expiry = datetime.datetime.utcnow() + datetime.timedelta(
        hours=current_app.config["JWT_EXPIRY_HOURS"]
    )
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "csrf_token": csrf_token,
        "iat": datetime.datetime.utcnow(),
        "exp": expiry,
    }
    token = jwt.encode(
        payload,
        current_app.config["JWT_SECRET_KEY"],
        algorithm="HS256",
    )
    return token, csrf_token


def decode_token(token: str) -> dict | None:
    """
    Decode and validate the JWT.
    Returns the payload dict or None if invalid/expired.
    jwt.decode() raises ExpiredSignatureError, InvalidTokenError, etc.
    """
    try:
        return jwt.decode(
            token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def set_auth_cookie(response, jwt_token: str):
    """
    Attach the JWT as an httpOnly, Secure, SameSite=Strict cookie.

    Security rationale:
      httpOnly  — cannot be read by JavaScript; mitigates XSS token theft.
      Secure    — only sent over TLS/HTTPS.
      SameSite=Strict — not attached on cross-origin navigations; CSRF defence.
    """
    response.set_cookie(
        "access_token",
        jwt_token,
        httponly=True,
        secure=not current_app.config.get("DEBUG", False),  # False in dev (HTTP), True in prod
        samesite="Strict",
        max_age=int(current_app.config["JWT_EXPIRY_HOURS"] * 3600),
        path="/",
    )
    return response


def clear_auth_cookie(response):
    response.delete_cookie("access_token", path="/")
    return response


# ── Current user ─────────────────────────────────────────────────────────────

def get_current_user() -> dict | None:
    """
    Read and decode the JWT from the cookie.
    Returns the decoded payload dict or None.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    return decode_token(token)


# ── CSRF token helpers ────────────────────────────────────────────────────────

def get_csrf_token() -> str | None:
    """Extract the CSRF token from the current user's JWT."""
    user = get_current_user()
    if user:
        return user.get("csrf_token")
    return None


def validate_csrf(request_obj) -> bool:
    """
    Synchronizer Token Pattern validation.

    The CSRF token submitted with the form (or X-CSRF-Token header for AJAX)
    must match the one embedded in the JWT. Because the JWT is httpOnly, an
    attacker cannot read the token from another origin — their forged request
    will have no valid token.
    """
    current_user = get_current_user()
    if not current_user:
        return False

    expected = current_user.get("csrf_token")
    # Accept token from form field or custom header (for AJAX)
    submitted = (
        request_obj.form.get("_csrf_token")
        or request_obj.headers.get("X-CSRF-Token")
    )
    if not expected or not submitted:
        return False
    # Use hmac.compare_digest equivalent — secrets.compare_digest is constant-time
    return secrets.compare_digest(expected, submitted)


# ── Route decorators ──────────────────────────────────────────────────────────

def login_required(f):
    """
    OWASP A01: Server-side authentication check on every protected route.
    Redirects unauthenticated users to the login page.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("auth.login"))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """
    OWASP A01: Role-Based Access Control enforced server-side.
    Returns 403 for authenticated non-admin users; redirects anon users.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash("Please log in to access that page.", "warning")
            return redirect(url_for("auth.login"))
        if user.get("role") != "admin":
            # Do not reveal the admin path exists — return generic 403
            from flask import abort
            abort(403)
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


def csrf_protect(f):
    """
    Decorator to validate CSRF token on state-changing requests (POST etc.).
    Apply to any route that modifies state — belt-and-suspenders on top of
    SameSite=Strict.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if not validate_csrf(request):
                from flask import abort
                abort(403)
        return f(*args, **kwargs)
    return decorated
