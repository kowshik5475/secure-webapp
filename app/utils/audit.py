"""
utils/audit.py — Structured audit logging helpers.

OWASP A09 — Security Logging and Monitoring Failures:
  Every security-relevant event is written to the audit_log table with:
    - ISO timestamp
    - Event type (machine-readable)
    - Affected user (user_id)
    - Actor (actor_id — relevant for admin actions)
    - Client IP address
    - Human-readable details string

  Events captured:
    register          — new account created
    login_success     — successful authentication
    login_fail        — failed login attempt (wrong password)
    login_locked      — login attempt on a locked account
    login_ratelimited — request hit the rate limit
    logout            — session terminated
    role_change       — admin changed a user's role
    upload_success    — file successfully uploaded
    upload_rejected   — file rejected (bad type, size, etc.)
    admin_action      — catch-all for admin panel operations

  Logging failed logins is critical: it enables detection of brute-force
  attacks, credential stuffing, and account enumeration attempts.
"""
from flask import request
from app.models import write_audit_log


def _get_ip() -> str:
    """
    Return the real client IP, respecting X-Forwarded-For when behind a
    trusted reverse proxy (like Nginx or a cloud load balancer).
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can be a comma-separated list; take the first
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def log_register(user_id: int, email: str):
    write_audit_log(
        event_type="register",
        user_id=user_id,
        ip_address=_get_ip(),
        details=f"New account created: {email}",
    )


def log_login_success(user_id: int, email: str):
    write_audit_log(
        event_type="login_success",
        user_id=user_id,
        ip_address=_get_ip(),
        details=f"Successful login: {email}",
    )


def log_login_fail(user_id: int | None, email: str):
    write_audit_log(
        event_type="login_fail",
        user_id=user_id,
        ip_address=_get_ip(),
        details=f"Failed login attempt for: {email}",
    )


def log_login_locked(user_id: int, email: str):
    write_audit_log(
        event_type="login_locked",
        user_id=user_id,
        ip_address=_get_ip(),
        details=f"Login attempt on locked account: {email}",
    )


def log_logout(user_id: int, email: str):
    write_audit_log(
        event_type="logout",
        user_id=user_id,
        ip_address=_get_ip(),
        details=f"User logged out: {email}",
    )


def log_role_change(target_user_id: int, actor_id: int, old_role: str, new_role: str):
    write_audit_log(
        event_type="role_change",
        user_id=target_user_id,
        actor_id=actor_id,
        ip_address=_get_ip(),
        details=f"Role changed from '{old_role}' to '{new_role}'",
    )


def log_upload_success(user_id: int, original_name: str, mime_type: str, size: int):
    write_audit_log(
        event_type="upload_success",
        user_id=user_id,
        ip_address=_get_ip(),
        details=f"File uploaded: '{original_name}' ({mime_type}, {size} bytes)",
    )


def log_upload_rejected(user_id: int, original_name: str, reason: str):
    write_audit_log(
        event_type="upload_rejected",
        user_id=user_id,
        ip_address=_get_ip(),
        details=f"File rejected: '{original_name}' — {reason}",
    )


def log_admin_action(actor_id: int, action: str, details: str):
    write_audit_log(
        event_type="admin_action",
        actor_id=actor_id,
        ip_address=_get_ip(),
        details=f"{action}: {details}",
    )
