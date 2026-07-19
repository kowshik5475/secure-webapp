# Secure Web Application — OWASP Top 10 Portfolio

A production-grade Flask application demonstrating every OWASP Top 10 mitigation
with clean, interview-ready code. Each security control is annotated with the
corresponding OWASP category and a rationale you can speak to directly.

---

## Architecture

```
artifacts/secure-webapp/
├── app/
│   ├── __init__.py          # App factory (create_app pattern)
│   ├── models.py            # Database access — parameterized queries only
│   ├── auth/routes.py       # Register, login, logout
│   ├── main/routes.py       # Dashboard, home
│   ├── admin/routes.py      # Admin panel — RBAC enforced
│   ├── uploads/routes.py    # File upload with magic-byte validation
│   ├── utils/
│   │   ├── auth.py          # JWT helpers, CSRF, @login_required, @admin_required
│   │   ├── security.py      # Security headers (CSP, HSTS, etc.)
│   │   └── audit.py         # Structured audit logging
│   └── templates/           # Jinja2 templates with auto-escaping
├── static/
│   ├── css/style.css
│   └── js/csrf.js           # Automatic CSRF token injection for AJAX
├── instance/app.db          # SQLite database (outside web root, gitignored)
├── uploads/                 # Uploaded files (outside web root, gitignored)
├── config.py                # Environment-aware configuration
├── run.py                   # Entry point
└── seed.py                  # Create demo accounts
```

### Key design decisions

- **App factory pattern** (`create_app()`) — enables multiple instances for testing,
  avoids circular imports, and keeps extension initialization explicit.
- **Blueprint-per-feature** — auth, main, admin, uploads are each a Flask Blueprint.
  Separation of concerns; each can be tested independently.
- **Raw SQLite + parameterized queries** — no ORM by design, so you can clearly point
  to the `?` placeholder pattern in interviews. Every query is explicit.
- **JWT embedded CSRF token** — the CSRF token is a claim inside the signed JWT. An
  attacker cannot forge it without the JWT secret, and cannot read it across origins.

---

## Quick Start

```bash
cd artifacts/secure-webapp
python seed.py          # Creates instance/app.db and two demo accounts
python run.py           # Starts on port 5000
```

Demo accounts (development only — change in production):

| Email                | Password   | Role  |
|----------------------|------------|-------|
| admin@example.com    | Admin1234! | admin |
| user@example.com     | User1234!  | user  |

---

## Security Controls — OWASP Top 10 Mapping

### A01 — Broken Access Control

**Mitigation: Role-Based Access Control enforced server-side**

- Every protected route is decorated with `@login_required` or `@admin_required`.
- Role is read from the **signed JWT** — it cannot be forged client-side.
- The admin panel (`/admin/*`) returns HTTP 403 for authenticated non-admin users;
  it does not reveal that the endpoint exists.
- Role-change endpoint validates the new role against an explicit allowlist
  (`{"user", "admin"}`) — raw form input is never trusted for privilege decisions.
- An admin cannot demote their own account (prevents accidental lockout).

```python
# app/utils/auth.py
@admin_required  # Checks JWT role server-side on every request
def change_role(target_id):
    new_role = request.form.get("role")
    if new_role not in VALID_ROLES:          # Allowlist, not denylist
        abort(403)
```

**Interview talking point:** "Client-side role checks are UX, not security. The server
re-validates the role from the signed token on every request — a modified cookie or
tampered DOM cannot escalate privileges."

---

### A02 — Cryptographic Failures

**Mitigation: bcrypt password hashing (never store plaintext)**

- Passwords are hashed with `bcrypt` (work factor 12) before any database write.
- bcrypt automatically generates and embeds a per-password salt — rainbow tables are
  ineffective even if the entire database is leaked.
- The work factor is adaptive: raising it from 12 to 14 increases cracking time by 4×
  without changing the API. Production config uses 14.
- JWTs are signed with HS256 using a 256-bit secret key loaded from an environment
  variable. Development falls back to a fresh `secrets.token_hex(32)` per restart.

```python
# app/models.py
pw_hash = bcrypt.hashpw(
    password.encode("utf-8"),
    bcrypt.gensalt(rounds=12),  # Each password gets a unique salt
).decode("utf-8")
```

**Interview talking point:** "MD5 and SHA-1 are fast by design — an attacker with a
GPU can test billions per second. bcrypt is deliberately slow. The work factor means
you can raise the cost as hardware improves without changing stored hashes."

---

### A03 — Injection (SQL Injection)

**Mitigation: Parameterized queries — no string concatenation**

- Every SQL statement uses `?` placeholders. User input is passed as a separate
  tuple to `conn.execute()`, never concatenated into the query string.
- SQLite's C-level API treats parameterized values as **data**, not as SQL syntax —
  no amount of quoting tricks can turn a value into an executable statement.

```python
# app/models.py — CORRECT
conn.execute("SELECT * FROM users WHERE email = ?", (email,))

# What we NEVER do
conn.execute(f"SELECT * FROM users WHERE email = '{email}'")  # ← injectable
```

**Interview talking point:** "Parameterized queries are a structural fix, not input
sanitization. Even if the attacker passes `' OR '1'='1`, SQLite treats it as a literal
string to compare against the email column — it never parses it as SQL."

---

### A04 — Insecure Design / File Upload

**Mitigation: Magic-byte validation, UUID filenames, out-of-web-root storage**

Three independent controls, any one of which stops common attacks:

1. **Magic bytes** (`filetype` library): the file's first bytes are inspected to
   determine its actual MIME type. A PHP webshell renamed to `shell.jpg` will have
   PHP content at byte 0 — `filetype.guess()` returns `None` or the wrong type and
   the file is rejected.

2. **UUID filenames**: the original filename is discarded entirely. The stored name
   is a `uuid.uuid4().hex` string (e.g. `a3f8c2d1...abcd.png`). Path traversal
   payloads like `../../etc/passwd` never reach the filesystem.

3. **Out-of-web-root storage**: files land in `uploads/` at the project root — not
   in `static/`. Flask never serves files from that directory. Even if a malicious
   file were stored, it has no URL to be accessed via the browser.

```python
# app/uploads/routes.py
kind = filetype.guess(file_bytes)   # Checks magic bytes
safe_name = f"{uuid.uuid4().hex}{ext}"   # Discard original filename
dest = os.path.join(app.config["UPLOAD_FOLDER"], safe_name)  # Outside web root
```

---

### A05 — Security Misconfiguration

**Mitigation: Secure HTTP headers + httpOnly JWT cookie**

**HTTP headers** (`app/utils/security.py`, applied to every response):

| Header | Value | Protects against |
|--------|-------|-----------------|
| `Content-Security-Policy` | `default-src 'self'` | XSS script injection |
| `X-Content-Type-Options` | `nosniff` | MIME-type sniffing of uploads |
| `X-Frame-Options` | `DENY` | Clickjacking |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | URL leakage |
| `Permissions-Policy` | `geolocation=(), camera=()…` | Unauthorized feature use |
| `Strict-Transport-Security` | `max-age=31536000` | SSL stripping |
| `Cache-Control` | `no-store` | Cached authenticated pages on shared devices |

**JWT cookie flags**:

```python
response.set_cookie(
    "access_token", jwt_token,
    httponly=True,    # JS cannot read it → XSS cannot steal the session
    secure=True,      # Only sent over HTTPS
    samesite="Strict" # Browser won't attach on cross-origin requests → CSRF defence
)
```

**Interview talking point:** "localStorage is accessible from JavaScript — any XSS
payload can steal tokens stored there. An httpOnly cookie is not readable by JS even
if the attacker injects a script. SameSite=Strict means the cookie isn't sent on
cross-site requests, which eliminates most CSRF vectors."

---

### A06 — Vulnerable and Outdated Components

**Mitigation: Pinned dependencies in requirements.txt**

- All packages are pinned with `>=` lower bounds, allowing patch updates.
- `pip audit` (or `safety check`) should be run in CI to detect CVEs.
- The `filetype` library (pure Python, no native code, minimal attack surface)
  was chosen over `python-magic` specifically to avoid a C dependency that could
  harbour its own vulnerabilities.

---

### A07 — Identification and Authentication Failures

**Mitigation: Rate limiting + account lockout + timing-safe comparison**

- Login endpoint: `@limiter.limit("10 per minute")` — brute force is throttled.
- After 5 consecutive failures: account locked for 15 minutes, lockout recorded
  in audit log, and unlock is automatic once the window expires.
- **Timing-safe not-found path**: if the email doesn't exist, we still call
  `bcrypt.checkpw()` against a dummy hash. This ensures the response time is the
  same whether the email exists or not — eliminating user-enumeration via timing.
- Error messages are generic: "Invalid email or password" — never "email not found"
  or "wrong password" (prevents account enumeration).

```python
# app/auth/routes.py
DUMMY_HASH = "$2b$12$invalidhashpaddingtomakeconstanttime///////padding"
stored_hash = user["password_hash"] if user else DUMMY_HASH
password_correct = verify_password(password, stored_hash)  # Always runs
```

---

### A08 — Software and Data Integrity Failures

**Mitigation: JWT signature verification; CSRF synchronizer token**

- JWTs are verified on every request with `jwt.decode(..., algorithms=["HS256"])`.
  A tampered payload will fail HMAC verification and be rejected.
- Algorithm is explicitly specified — prevents the "alg: none" attack where an
  attacker strips the signature and sets the algorithm to none.

---

### A09 — Security Logging and Monitoring Failures

**Mitigation: Structured audit log for all security events**

Every security-relevant event is written to `audit_log` with:
- ISO 8601 timestamp
- Machine-readable `event_type`
- `user_id` (affected user)
- `actor_id` (who performed the action — for admin actions)
- Client IP (X-Forwarded-For aware)
- Human-readable `details`

Events captured: `register`, `login_success`, `login_fail`, `login_locked`,
`login_ratelimited`, `logout`, `role_change`, `upload_success`, `upload_rejected`,
`admin_action`.

**Interview talking point:** "Logging failed logins is the primary signal for detecting
credential stuffing and brute-force attacks. Without it, an attacker can make thousands
of attempts before anyone notices. In production this log would stream to a SIEM."

---

### A10 — Server-Side Request Forgery (SSRF)

**Mitigation: No outbound requests initiated by user input**

This application does not accept URLs from users or make outbound HTTP requests.
The file upload validates content server-side without following any URLs. The CSRF
token prevents attackers from initiating state-changing requests from other origins.

---

### CSRF — Cross-Site Request Forgery

**Mitigation: Synchronizer Token Pattern (belt-and-suspenders with SameSite=Strict)**

Layer 1 — **SameSite=Strict cookie**: the browser won't attach the JWT cookie on
cross-origin requests at all.

Layer 2 — **Synchronizer Token**: a random token is embedded in the JWT payload.
Every state-changing form renders it as a hidden field (`_csrf_token`). The server
validates it on every POST/PUT/PATCH/DELETE.

```html
<!-- Every state-changing form -->
<input type="hidden" name="_csrf_token" value="{{ current_user.csrf_token }}">
```

Layer 3 — **AJAX patching** (`static/js/csrf.js`): `fetch()` and `XMLHttpRequest`
are monkey-patched to automatically attach `X-CSRF-Token` on same-origin
state-mutating requests.

---

### XSS — Cross-Site Scripting

**Mitigation: Jinja2 auto-escaping + Content-Security-Policy**

- Jinja2 auto-escapes all `{{ variable }}` expressions in `.html` templates.
  `<script>` in user data renders as `&lt;script&gt;` — it can never execute.
- `| safe` is never used on user-supplied data anywhere in the codebase.
- CSP header `default-src 'self'; script-src 'self'` prevents inline script
  execution and cross-origin script loading as a defence-in-depth layer.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Production | Flask session signing key (32+ bytes hex) |
| `JWT_SECRET_KEY` | Production | JWT HMAC signing key (32+ bytes hex) |
| `FLASK_ENV` | Optional | Set to `production` to use ProductionConfig |
| `PORT` | Optional | Port to bind to (default: 5000) |

Generate strong keys:
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Running Tests

```bash
# Install dev dependencies
pip install pytest

# Run tests
pytest tests/
```

---

## Known Limitations

### Role changes don't take effect until JWT expiry

This app uses **stateless JWTs**: the user's role is embedded as a signed claim
inside the token. When an admin promotes or demotes a user, the change is written
to the database immediately — but the user's existing token still contains the old
role and will be accepted until it expires (up to 1 hour by default).

**Why it's a fundamental stateless-JWT tradeoff:**
Validating the token locally (no DB round-trip on every request) is the core
performance benefit of JWTs. Adding a revocation check reintroduces a per-request
DB call, at which point a signed session cookie + server-side session table is
simpler and equally fast.

**Standard mitigations (next steps):**

1. **Shorter token TTL** — Reduce `JWT_EXPIRY_HOURS` to e.g. 5–15 minutes. The
   user re-authenticates more often but the exposure window after a role change
   shrinks proportionally. This is the simplest fix and costs nothing to implement.

2. **Server-side deny-list** — Keep a `revoked_tokens` table (or Redis set) keyed
   by `jti` (JWT ID claim). On every request, check whether the token's `jti` is
   in the deny-list before trusting its claims. Add a `jti` UUID claim to
   `generate_token()`, and populate the deny-list in `change_role()`. Entries can
   be expired automatically after `JWT_EXPIRY_HOURS` to keep the table small.

3. **Version claim** — Store a `token_version` integer on the user row. Embed it
   as a JWT claim. On each request, load the user's current `token_version` from
   the DB and reject the token if the claim doesn't match. A role change bumps
   the version, instantly invalidating all existing tokens for that user.

For this portfolio project the 1-hour window is acceptable and is documented here
as an intentional tradeoff of the stateless architecture.

---

## Production Checklist

- [ ] Set `SECRET_KEY` and `JWT_SECRET_KEY` as environment variables
- [ ] Set `FLASK_ENV=production`
- [ ] Run behind a TLS-terminating reverse proxy (Nginx, Caddy)
- [ ] Enable HSTS preloading after confirming HTTPS works
- [ ] Run `pip audit` to check for vulnerable dependencies
- [ ] Replace SQLite with PostgreSQL for multi-process deployments
- [ ] Send `audit_log` to a SIEM or log aggregation service
- [ ] Set up alerts for `login_fail` spikes and `role_change` events
- [ ] Review and tighten the CSP `style-src` (remove `unsafe-inline`)
