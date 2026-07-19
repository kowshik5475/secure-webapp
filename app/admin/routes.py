"""
admin/routes.py — Admin-only routes.

OWASP A01 — Broken Access Control:
  The @admin_required decorator enforces role checks server-side on every
  route. Roles are read from the JWT, which is signed — it cannot be
  tampered with client-side.

OWASP A04 — Insecure Design:
  Role-change endpoint validates the new_role value against an explicit
  allowlist — never trusts raw form input for privilege decisions.

OWASP A09 — Security Logging:
  Every admin action (role change, viewing audit log) is recorded.
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from app.utils.auth import admin_required, get_current_user, csrf_protect
from app.models import get_all_users, get_user_by_id, update_user_role, get_recent_audit_log
from app.utils.audit import log_role_change, log_admin_action

admin_bp = Blueprint("admin", __name__)

VALID_ROLES = {"user", "admin"}


@admin_bp.route("/")
@admin_required
def dashboard():
    user = get_current_user()
    users = get_all_users()
    recent_logs = get_recent_audit_log(limit=20)
    log_admin_action(
        actor_id=user["sub"],
        action="admin_dashboard_view",
        details="Admin viewed the dashboard",
    )
    return render_template(
        "admin/dashboard.html",
        current_user=user,
        users=users,
        recent_logs=recent_logs,
    )


@admin_bp.route("/users")
@admin_required
def users():
    user = get_current_user()
    all_users = get_all_users()
    return render_template("admin/users.html", current_user=user, users=all_users)


@admin_bp.route("/users/<int:target_id>/role", methods=["POST"])
@admin_required
@csrf_protect
def change_role(target_id: int):
    """
    OWASP A01: Role-change restricted to admins only.
    OWASP A04: new_role validated against explicit allowlist — never blind-trusts form input.
    OWASP A09: Role change is written to the audit log.
    """
    actor = get_current_user()
    new_role = request.form.get("role", "").strip()

    # ── Allowlist validation — never trust raw form input for roles ───────────
    if new_role not in VALID_ROLES:
        flash("Invalid role value.", "error")
        return redirect(url_for("admin.users"))

    target = get_user_by_id(target_id)
    if not target:
        flash("User not found.", "error")
        return redirect(url_for("admin.users"))

    # Prevent admin from downgrading their own account
    if target_id == actor["sub"] and new_role != "admin":
        flash("You cannot remove your own admin role.", "error")
        return redirect(url_for("admin.users"))

    old_role = target["role"]
    if old_role == new_role:
        flash("User already has that role.", "info")
        return redirect(url_for("admin.users"))

    update_user_role(target_id, new_role)
    log_role_change(
        target_user_id=target_id,
        actor_id=actor["sub"],
        old_role=old_role,
        new_role=new_role,
    )

    flash(f"Role updated for {target['email']}: {old_role} → {new_role}", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/audit-log")
@admin_required
def audit_log():
    user = get_current_user()
    logs = get_recent_audit_log(limit=200)
    return render_template("admin/audit_log.html", current_user=user, logs=logs)
