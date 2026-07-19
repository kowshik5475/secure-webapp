"""
utils/security.py — Secure HTTP response headers.

OWASP A05 — Security Misconfiguration:
  Missing security headers are one of the most common misconfigurations.
  These headers are applied to every response via app.after_request().

Header-by-header rationale
──────────────────────────
Content-Security-Policy (CSP)
    Instructs browsers which sources are allowed for scripts, styles, etc.
    Prevents injected scripts from running (defence-in-depth against XSS).
    default-src 'self' — only resources from the same origin are allowed.

X-Content-Type-Options: nosniff
    Prevents browsers from MIME-type sniffing a response away from the
    declared Content-Type. Stops execution of uploaded files as HTML/JS.

X-Frame-Options: DENY
    Prevents the app from being embedded in an <iframe>.
    Mitigates clickjacking attacks.

Referrer-Policy: strict-origin-when-cross-origin
    Limits how much URL information is sent to third-party sites via the
    Referer header (avoids leaking session-state in URLs).

Permissions-Policy
    Opts out of browser features (camera, microphone, geolocation) the app
    doesn't use. Reduces the attack surface if a script injection occurs.

Strict-Transport-Security (HSTS)
    Tells browsers to only connect via HTTPS for the next year.
    Prevents SSL-stripping man-in-the-middle attacks.

Cache-Control: no-store
    Prevents browsers from caching authenticated pages. Stops cached content
    from being visible if a shared device is used.
"""
from flask import Response, current_app


def apply_security_headers(response: Response) -> Response:
    """
    Apply all security headers. Called via app.after_request() so every
    response — regardless of blueprint — gets them.
    """
    # ── Content Security Policy ───────────────────────────────────────────────
    # Adjust 'unsafe-inline' for styles only if you add inline CSS.
    # For production, move inline styles to a stylesheet and remove 'unsafe-inline'.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )

    # ── Anti-MIME-sniffing ────────────────────────────────────────────────────
    response.headers["X-Content-Type-Options"] = "nosniff"

    # ── Clickjacking protection ───────────────────────────────────────────────
    response.headers["X-Frame-Options"] = "DENY"

    # ── Referrer leak prevention ──────────────────────────────────────────────
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # ── Feature/Permissions policy ────────────────────────────────────────────
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=()"
    )

    # ── HSTS (HTTPS enforcement) ──────────────────────────────────────────────
    # Only send in production. Dev typically uses plain HTTP; a browser that
    # sees HSTS over HTTP would refuse all future plain-HTTP connections to
    # that host for up to a year, breaking the dev workflow.
    if not current_app.config.get("DEBUG", False):
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains; preload"
        )

    # ── Cache control for authenticated content ───────────────────────────────
    if response.content_type and "text/html" in response.content_type:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

    # ── Remove server fingerprint ─────────────────────────────────────────────
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)

    return response
