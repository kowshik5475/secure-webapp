/**
 * csrf.js — CSRF token injection for AJAX requests.
 *
 * OWASP CSRF — Synchronizer Token Pattern (AJAX layer):
 *
 * HTML forms embed the CSRF token as a hidden field (_csrf_token).
 * For JavaScript fetch() / XHR calls that don't submit a form, we
 * automatically attach the token via the X-CSRF-Token header.
 *
 * The server's csrf_protect decorator checks:
 *   1. request.form.get('_csrf_token')   — for form submissions
 *   2. request.headers.get('X-CSRF-Token') — for AJAX requests
 *
 * Security note:
 *   The token is readable here because it's in a <meta> tag (not httpOnly).
 *   That's intentional: JavaScript needs it to attach to AJAX headers.
 *   The JWT itself is in an httpOnly cookie and is NEVER accessible to JS.
 *   An attacker on another origin:
 *     - Cannot read the meta tag (same-origin policy).
 *     - Cannot forge the token (it's derived from the signed JWT).
 *     - SameSite=Strict prevents the cookie being sent cross-origin at all.
 */

(function () {
  'use strict';

  /**
   * Read the CSRF token from the <meta name="csrf-token"> tag.
   * Returns empty string if user is unauthenticated (no token in DOM).
   */
  function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  /**
   * Patch the global fetch() to automatically attach X-CSRF-Token
   * on state-changing requests to the same origin.
   */
  const originalFetch = window.fetch;
  window.fetch = function (url, options) {
    options = options || {};

    const method = (options.method || 'GET').toUpperCase();
    const stateMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method);

    // Only attach token to same-origin state-mutating requests.
    if (stateMutating && isSameOrigin(url)) {
      options.headers = options.headers || {};
      // Support Headers object or plain object
      if (options.headers instanceof Headers) {
        if (!options.headers.has('X-CSRF-Token')) {
          options.headers.set('X-CSRF-Token', getCsrfToken());
        }
      } else {
        if (!options.headers['X-CSRF-Token']) {
          options.headers['X-CSRF-Token'] = getCsrfToken();
        }
      }
    }

    return originalFetch.call(this, url, options);
  };

  /**
   * Check if a URL is same-origin as the current page.
   */
  function isSameOrigin(url) {
    try {
      const target = new URL(url, window.location.href);
      return target.origin === window.location.origin;
    } catch (_) {
      // Relative URLs are always same-origin
      return true;
    }
  }

  /**
   * Also patch XMLHttpRequest for legacy code.
   */
  const OrigXHR = window.XMLHttpRequest;
  const xhrOpen = OrigXHR.prototype.open;
  const xhrSend = OrigXHR.prototype.send;

  OrigXHR.prototype.open = function (method, url) {
    this._csrfMethod = method ? method.toUpperCase() : 'GET';
    this._csrfUrl = url;
    return xhrOpen.apply(this, arguments);
  };

  OrigXHR.prototype.send = function () {
    const stateMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(this._csrfMethod);
    if (stateMutating && isSameOrigin(this._csrfUrl || '')) {
      this.setRequestHeader('X-CSRF-Token', getCsrfToken());
    }
    return xhrSend.apply(this, arguments);
  };
})();
