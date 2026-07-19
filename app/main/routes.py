"""
main/routes.py — Public landing page and authenticated user dashboard.
"""
from flask import Blueprint, render_template, g
from app.utils.auth import login_required, get_current_user
from app.models import get_user_files, get_user_by_id

main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    user = get_current_user()
    return render_template("main/index.html", current_user=user)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    # Fetch fresh user record from DB (role may have changed since JWT was issued)
    db_user = get_user_by_id(user["sub"])
    files = get_user_files(user["sub"])
    return render_template(
        "main/dashboard.html",
        current_user=user,
        db_user=db_user,
        files=files,
    )
