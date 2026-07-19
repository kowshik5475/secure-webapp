/**
 * ui.js — Non-security-critical UI behavior, loaded as an external script.
 *
 * Why this file exists:
 *   The app's Content-Security-Policy sets `script-src 'self'` with no
 *   'unsafe-inline'. That's intentional — it's a real XSS defence-in-depth
 *   layer (see utils/security.py). The tradeoff is that inline <script>
 *   blocks and onclick="..." attributes are silently blocked by the browser
 *   and will never run. Rather than weaken the CSP to allow inline JS
 *   (which would undercut the exact protection it's there for), all
 *   interactive UI behavior lives here instead, loaded via a normal
 *   <script src="..."> tag — which 'self' already permits.
 */

(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    initFlashDismiss();
    initPasswordToggles();
    initPasswordStrengthMeter();
    initUploadDropzone();
  });

  // ── Flash message dismissal ──────────────────────────────────────────────
  // Replaces: onclick="this.parentElement.remove()"
  function initFlashDismiss() {
    document.querySelectorAll('.flash-close').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var flash = btn.closest('.flash');
        if (flash) flash.remove();
      });
    });
  }

  // ── Show/Hide password toggles ───────────────────────────────────────────
  // Replaces: onclick="togglePassword('password', this)"
  // Buttons declare their target input via data-target="<input id>" instead
  // of an inline handler.
  function initPasswordToggles() {
    document.querySelectorAll('.show-pw-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var targetId = btn.getAttribute('data-target');
        var input = document.getElementById(targetId);
        if (!input) return;

        if (input.type === 'password') {
          input.type = 'text';
          btn.textContent = 'Hide';
        } else {
          input.type = 'password';
          btn.textContent = 'Show';
        }
      });
    });
  }

  // ── Password strength indicator (register page) ─────────────────────────
  // UX only — NOT a security control. Real strength rules are enforced
  // server-side in auth/routes.py validate_password(); this is just feedback.
  // Only runs when #pw-strength exists (register page), no-ops elsewhere.
  function initPasswordStrengthMeter() {
    var passwordInput = document.getElementById('password');
    var strengthEl = document.getElementById('pw-strength');
    if (!passwordInput || !strengthEl) return;

    passwordInput.addEventListener('input', function () {
      var val = passwordInput.value;
      var strength = 0;
      if (val.length >= 8) strength++;
      if (/[A-Z]/.test(val)) strength++;
      if (/\d/.test(val)) strength++;
      if (/[!@#$%^&*(),.?":{}|<>_\-]/.test(val)) strength++;

      var labels = ['', 'Weak', 'Fair', 'Good', 'Strong'];
      var classes = ['', 'pw-weak', 'pw-fair', 'pw-good', 'pw-strong'];

      strengthEl.textContent = val.length > 0 ? labels[strength] : '';
      strengthEl.className = 'pw-strength ' + (val.length > 0 ? classes[strength] : '');
    });
  }

  // ── Upload dropzone (drag-and-drop) ──────────────────────────────────────
  // Only runs on the upload page — no-ops elsewhere since #dropzone won't exist.
  function initUploadDropzone() {
    var dropzone = document.getElementById('dropzone');
    var input = document.getElementById('file-input');
    var filenameLabel = document.getElementById('dropzone-filename');
    if (!dropzone || !input || !filenameLabel) return;

    function showFilename() {
      if (input.files && input.files.length > 0) {
        filenameLabel.textContent = input.files[0].name;
        dropzone.classList.add('dropzone-has-file');
      }
    }

    dropzone.addEventListener('click', function () { input.click(); });
    input.addEventListener('change', showFilename);

    ['dragenter', 'dragover'].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.add('dropzone-dragover');
      });
    });

    ['dragleave', 'drop'].forEach(function (evt) {
      dropzone.addEventListener(evt, function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('dropzone-dragover');
      });
    });

    dropzone.addEventListener('drop', function (e) {
      var dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        input.files = dt.files;
        showFilename();
      }
    });
  }
})();
