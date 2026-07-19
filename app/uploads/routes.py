"""
uploads/routes.py — Authenticated file upload with defence-in-depth validation.

OWASP A04 — Insecure Design:
  Three independent controls, any one of which stops common attacks:
    1. Magic-byte inspection (filetype.guess) — the file's real content is
       checked, never the client-supplied extension or Content-Type header.
    2. UUID-generated stored filename — the original filename never touches
       disk. Path-traversal payloads in the original name (e.g. "../../x")
       cannot affect the stored path.
    3. Storage in UPLOAD_FOLDER, which lives outside static/ and templates/
       and is never registered as a Flask route — stored files have no
       accessible URL, so even a file that slipped past (1) and (2) can't
       be executed by requesting it directly.

OWASP A01 — Broken Access Control:
  Upload requires @login_required. Every uploaded_files row is scoped to
  the uploading user_id; a user can only ever see their own files.

OWASP A09 — Security Logging:
  Every accepted and rejected upload is written to the audit log.
"""
import os
import uuid

import filetype
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, current_app,
)

from app.utils.auth import login_required, get_current_user, csrf_protect
from app.models import store_uploaded_file, get_user_files
from app.utils.audit import log_upload_success, log_upload_rejected

uploads_bp = Blueprint("uploads", __name__)

# Extension used for the stored filename, keyed by detected MIME type.
# Deliberately NOT derived from the client-supplied filename.
_EXT_BY_MIME = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "application/pdf": ".pdf",
}


@uploads_bp.route("/", methods=["GET"])
@login_required
def upload():
    """Render the upload form and the current user's file list."""
    user = get_current_user()
    files = get_user_files(user["sub"])
    return render_template("uploads/upload.html", current_user=user, files=files)


@uploads_bp.route("/", methods=["POST"])
@login_required
@csrf_protect
def upload_post():
    """
    Handle the actual upload.

    Flask's MAX_CONTENT_LENGTH config enforces a hard size cap before this
    view even runs (Werkzeug raises 413 RequestEntityTooLarge). Everything
    below assumes a request that was allowed through the size gate.
    """
    user = get_current_user()

    uploaded = request.files.get("file")
    if uploaded is None or uploaded.filename == "":
        flash("No file selected.", "error")
        return redirect(url_for("uploads.upload"))

    original_name = uploaded.filename

    # ── Control 1: magic-byte inspection ───────────────────────────────────
    # Read the file's actual content signature — never trust the client's
    # Content-Type header or the filename extension, both of which an
    # attacker fully controls. filetype.guess() reads the first 261 bytes.
    header = uploaded.stream.read(261)
    uploaded.stream.seek(0)
    kind = filetype.guess(header)

    detected_mime = kind.mime if kind else None
    allowed_mimes = current_app.config["ALLOWED_MIME_TYPES"]

    if detected_mime not in allowed_mimes:
        log_upload_rejected(
            user_id=user["sub"],
            original_name=original_name,
            reason=f"disallowed or undetectable file type (detected: {detected_mime or 'unknown'})",
        )
        flash("That file type isn't allowed. Only PNG, JPEG, GIF, and PDF are accepted.", "error")
        return redirect(url_for("uploads.upload"))

    # ── Control 2: UUID-generated stored filename ──────────────────────────
    # The original name is kept only as a display-only DB column (rendered
    # with Jinja2 auto-escaping) — it never becomes part of a filesystem path.
    stored_name = f"{uuid.uuid4().hex}{_EXT_BY_MIME[detected_mime]}"

    # ── Control 3: store outside the web root ───────────────────────────────
    # UPLOAD_FOLDER (project_root/uploads/) is not inside static/ and has no
    # registered Flask route, so saved files are never directly fetchable.
    upload_folder = current_app.config["UPLOAD_FOLDER"]
    dest_path = os.path.join(upload_folder, stored_name)

    uploaded.save(dest_path)
    size_bytes = os.path.getsize(dest_path)

    store_uploaded_file(
        user_id=user["sub"],
        original_name=original_name,
        stored_name=stored_name,
        mime_type=detected_mime,
        size_bytes=size_bytes,
    )
    log_upload_success(
        user_id=user["sub"],
        original_name=original_name,
        mime_type=detected_mime,
        size=size_bytes,
    )

    flash(f"'{original_name}' uploaded successfully.", "success")
    return redirect(url_for("uploads.upload"))


@uploads_bp.errorhandler(413)
def file_too_large(_e):
    """Werkzeug raises 413 automatically when MAX_CONTENT_LENGTH is exceeded."""
    flash("File is too large. Maximum upload size is 5 MB.", "error")
    return redirect(url_for("uploads.upload")), 413
