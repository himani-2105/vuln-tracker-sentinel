"""Authentication, RBAC, CSRF, rate limiting, security headers, secret handling."""
import os, time, hmac, secrets, functools, collections, datetime as dt
from flask import session, request, g, jsonify, abort
from werkzeug.security import generate_password_hash, check_password_hash
import db

PERMS = {
 "admin": {"*"},
 "analyst": {"read", "upload", "finding.create", "finding.status", "finding.assign", "finding.verify", "finding.exploit", "finding.note", "finding.deadline",
             "exception.request", "exception.approve", "asset.edit", "relationship.edit", "export", "intel.read"},
 "owner": {"read", "finding.note", "finding.status_own", "exception.request"},
 "auditor": {"read", "audit.view", "export"},
}
def can(user, perm): 
    p = PERMS.get((user or {}).get("role"), set()); return "*" in p or perm in p

def load_secret_key(db_path, env):
    k = os.environ.get("SECRET_KEY")
    if k:
        if len(k) < 32: raise RuntimeError("SECRET_KEY must be at least 32 characters")
        return k
    if env == "production": raise RuntimeError("SECRET_KEY is required when VULNTRACK_ENV=production")
    f = os.path.abspath(db_path) + ".secret"          # dev/demo only: random key persisted next to the DB, never committed
    if os.path.exists(f): return open(f).read().strip()
    k = secrets.token_hex(32)
    fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh: fh.write(k)
    return k

def hash_pw(pw): return generate_password_hash(pw, method="scrypt")
def check_pw(h, pw): return check_password_hash(h, pw)
def validate_password(pw):
    if not isinstance(pw, str) or len(pw) < 12: return "password must be at least 12 characters"
    if len(pw) > 200: return "password too long"
    if len({c for c in pw}) < 5 or pw.lower() in ("password1234", "123456789012"): return "password is too weak"
    return None

# ---- CSRF: token bound to the session, required header on every unsafe API request ----
def csrf_token():
    if "csrf" not in session: session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]
def check_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS") or not request.path.startswith("/api/"): return
    sent = request.headers.get("X-CSRF-Token", ""); want = session.get("csrf", "")
    if not want or not hmac.compare_digest(sent, want): abort(403, "CSRF token missing or invalid")

# ---- current user ----
def current_user():
    if "user" in g: return g.user
    g.user = None; uid = session.get("uid")
    if uid:
        r = db_conn().execute("SELECT id,username,display_name,role,active FROM users WHERE id=?", (uid,)).fetchone()
        if r and r["active"]: g.user = dict(r)
        else: session.clear()
    return g.user
def db_conn():
    from app import get_db; return get_db()

def require(perm="read"):
    def deco(fn):
        @functools.wraps(fn)
        def w(*a, **k):
            u = current_user()
            if not u: return jsonify(error="authentication required"), 401
            if not can(u, perm): return jsonify(error="you do not have permission to do this"), 403
            return fn(*a, **k)
        return w
    return deco

# ---- rate limiting ----
_hits = collections.defaultdict(list)
def rate_limit(bucket, limit, window):
    def deco(fn):
        @functools.wraps(fn)
        def w(*a, **k):
            if os.environ.get("VULNTRACK_DISABLE_RATELIMIT"): return fn(*a, **k)
            key = (bucket, request.remote_addr); now = time.time()
            _hits[key] = [t for t in _hits[key] if now - t < window]
            if len(_hits[key]) >= limit: return jsonify(error="too many requests; slow down"), 429
            _hits[key].append(now); return fn(*a, **k)
        return w
    return deco
def reset_limits(): _hits.clear()

def login_locked(c, username, ip):
    since = (db.utcnow() - dt.timedelta(minutes=15)).isoformat(timespec="seconds")
    u = c.execute("SELECT COUNT(*) FROM login_attempts WHERE success=0 AND at>? AND username=?", (since, username.lower())).fetchone()[0]
    i = c.execute("SELECT COUNT(*) FROM login_attempts WHERE success=0 AND at>? AND ip=?", (since, ip)).fetchone()[0]
    return u >= 5 or i >= 25

def add_headers(resp):
    resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                              "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'")
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
                         "Permissions-Policy": "geolocation=(), camera=(), microphone=()", "Cross-Origin-Opener-Policy": "same-origin"})
    if request.path.startswith("/api/"): resp.headers["Cache-Control"] = "no-store"
    if os.environ.get("VULNTRACK_ENV") == "production": resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp
