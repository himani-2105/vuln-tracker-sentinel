"""VulnTrack Sentinel: Flask application factory. `gunicorn app:app` remains the entry point."""
import os, re, io, json, time, logging, datetime as dt
from flask import Flask, request, jsonify, Response, session, g, send_from_directory, current_app
import db, audit, risk, data, reports, workflow, security
from db import tx, now_iso, S_OPEN, S_ACCEPTED, S_REOPENED, S_VERIFIED, S_FIXED, UNRESOLVED
from parsers import parse_report, ReportError
from security import require, current_user, can

log = logging.getLogger("vulntrack")
def get_db():
    if "db" not in g: g.db = db.connect(current_app.config["DB_PATH"])
    return g.db

def create_app(overrides=None):
    app = Flask(__name__, static_folder="static", static_url_path="")
    env = os.environ.get("VULNTRACK_ENV", "development")
    app.config.update(DB_PATH=os.environ.get("DB_PATH", "tracker.db"), MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "30")) * 1024 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_SECURE=(env == "production"),
                      PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=int(os.environ.get("SESSION_HOURS", "8"))), JSON_SORT_KEYS=False,
                      DEMO_MODE=os.environ.get("VULNTRACK_DEMO") == "1", ENV=env)
    if overrides: app.config.update(overrides)
    app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or security.load_secret_key(app.config["DB_PATH"], env)
    logging.basicConfig(level=logging.INFO)
    c = db.migrate(app.config["DB_PATH"])
    if not c.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        u, p = os.environ.get("INITIAL_ADMIN_USERNAME"), os.environ.get("INITIAL_ADMIN_PASSWORD")
        if u and p and not security.validate_password(p):
            with tx(c): c.execute("INSERT INTO users(username,display_name,role,password_hash,created_at) VALUES(?,?,?,?,?)", (u, u, "admin", security.hash_pw(p), now_iso()))
            audit.log(c, workflow.SYSTEM, "user.bootstrap_admin", "user", u)
            log.info("initial admin '%s' created from environment (remove INITIAL_ADMIN_PASSWORD afterwards)", u)
        else: log.warning("No users exist. Run `python manage.py create-admin` or set INITIAL_ADMIN_USERNAME/INITIAL_ADMIN_PASSWORD (min 12 chars) once.")
    c.close()
    app.teardown_appcontext(lambda e: _close())
    app.before_request(security.check_csrf); app.after_request(security.add_headers)
    app.before_request(_housekeeping)
    for code, msg in ((400, "bad request"), (401, "authentication required"), (403, "forbidden"), (404, "not found"), (405, "method not allowed"), (413, "upload too large"), (429, "too many requests")):
        app.register_error_handler(code, lambda e, m=msg: (jsonify(error=(e.description if str(getattr(e, "description", "")).startswith("CSRF") else m)), e.code))
    app.register_error_handler(workflow.WorkflowError, lambda e: (jsonify(error=str(e)), e.code))
    app.register_error_handler(Exception, _server_error)
    register(app); return app

def _close():
    d = g.pop("db", None)
    if d is not None: d.close()
def _server_error(e):
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException): return jsonify(error=e.name.lower()), e.code
    log.exception("unhandled error on %s %s", request.method, request.path)       # details stay server-side
    return jsonify(error="internal server error"), 500
_last_hk = [0.0]
def _housekeeping():
    if request.path.startswith("/api/") and request.method == "GET" and time.time() - _last_hk[0] > 60:
        _last_hk[0] = time.time()
        try:
            c = get_db()
            with tx(c): workflow.expire_exceptions(c)
        except Exception: log.exception("housekeeping failed")

# ---------- helpers ----------
def body(): 
    j = request.get_json(silent=True)
    return j if isinstance(j, dict) else {}
def err(msg, code=400): return jsonify(error=msg), code
def txt(v, mx=2000): return v.strip()[:mx] if isinstance(v, str) else ""
def parse_date(s, name):
    try: return dt.date.fromisoformat(str(s)[:10])
    except Exception: raise workflow.WorkflowError(f"{name} must be a valid date (YYYY-MM-DD)")
def ip(): return request.remote_addr
def page_args(default=25):
    try: p = max(1, int(request.args.get("page", 1))); n = min(200, max(1, int(request.args.get("per_page", default))))
    except ValueError: p, n = 1, default
    return p, n
def paginate(items, p, n): return {"items": items[(p - 1) * n:p * n], "total": len(items), "page": p, "per_page": n, "pages": max(1, -(-len(items) // n))}
def finding_filters():
    a = request.args; f = {k: a[k] for k in ("severity", "status", "environment", "cve", "q", "category") if a.get(k)}
    for k in ("asset", "owner", "scan"):
        if a.get(k, "").isdigit(): f[k] = a[k]
    for k in ("age_min", "age_max"):
        if a.get(k, "").isdigit(): f[k] = int(a[k])
    if a.get("overdue") in ("1", "true"): f["overdue"] = True
    if a.get("unassigned") in ("1", "true"): f["unassigned"] = True
    return f
def asset_row(c, aid):
    r = c.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    return dict(r) if r else None

def register(app):
    @app.get("/")
    def home(): return app.send_static_file("index.html")

    @app.get("/health")
    def health():
        try:
            get_db().execute("SELECT 1").fetchone(); return jsonify(status="ok", db="ok", version="2.0", demo=current_app.config["DEMO_MODE"])
        except Exception: return jsonify(status="degraded", db="unavailable"), 503

    # ---------------- auth ----------------
    @app.get("/api/auth/me")
    def me():
        u = current_user()
        return jsonify(csrf=security.csrf_token(), user=u and {k: u[k] for k in ("id", "username", "display_name", "role")}, demo=current_app.config["DEMO_MODE"],
                       perms=sorted(security.PERMS.get(u["role"], [])) if u else [])

    @app.post("/api/auth/login")
    @security.rate_limit("login", 30, 300)
    def login():
        c = get_db(); b = body(); un = txt(b.get("username"), 80); pw = b.get("password") if isinstance(b.get("password"), str) else ""
        if not un or not pw: return err("username and password are required")
        if security.login_locked(c, un, ip()): return err("too many failed attempts; try again in 15 minutes", 429)
        u = c.execute("SELECT * FROM users WHERE username=?", (un,)).fetchone()
        ok = bool(u and u["active"] and security.check_pw(u["password_hash"], pw))
        with tx(c):
            c.execute("INSERT INTO login_attempts(at,username,ip,success) VALUES(?,?,?,?)", (now_iso(), un.lower(), ip(), int(ok)))
            audit.log(c, {"id": u["id"] if u else None, "username": un, "role": u["role"] if u else None}, "auth.login_success" if ok else "auth.login_failed", "user", u["id"] if u else None, ip=ip())
            if ok: c.execute("UPDATE users SET last_login=? WHERE id=?", (now_iso(), u["id"]))
        if not ok: return err("invalid username or password", 401)
        session.clear(); session.permanent = True; session["uid"] = u["id"]; g.pop("user", None)
        return jsonify(csrf=security.csrf_token(), user={"id": u["id"], "username": u["username"], "display_name": u["display_name"], "role": u["role"]})

    @app.post("/api/auth/logout")
    def logout():
        u = current_user()
        if u:
            c = get_db()
            with tx(c): audit.log(c, u, "auth.logout", "user", u["id"], ip=ip())
        session.clear(); return jsonify(ok=True)

    @app.post("/api/auth/password")
    @require("read")
    def change_pw():
        u = current_user(); b = body(); c = get_db(); row = c.execute("SELECT password_hash FROM users WHERE id=?", (u["id"],)).fetchone()
        if not security.check_pw(row[0], b.get("current") or ""): return err("current password is incorrect", 403)
        e = security.validate_password(b.get("new"))
        if e: return err(e)
        with tx(c): c.execute("UPDATE users SET password_hash=? WHERE id=?", (security.hash_pw(b["new"]), u["id"])); audit.log(c, u, "user.password_change", "user", u["id"], ip=ip())
        return jsonify(ok=True)

    # ---------------- users ----------------
    @app.get("/api/users")
    @require("read")
    def users():
        u = current_user(); c = get_db()
        cols = "id,username,display_name,role,active,created_at,last_login" if u["role"] == "admin" else "id,display_name,username,role"
        return jsonify([dict(r) for r in c.execute(f"SELECT {cols} FROM users " + ("" if u["role"] == "admin" else "WHERE active=1 ") + "ORDER BY username")])

    @app.post("/api/users")
    @require("users.manage")
    def user_create():
        b = body(); c = get_db(); un = txt(b.get("username"), 40)
        if not re.match(r"^[A-Za-z0-9_.@-]{3,40}$", un): return err("username must be 3-40 characters (letters, digits, . _ - @)")
        if b.get("role") not in ("admin", "analyst", "owner", "auditor"): return err("invalid role")
        e = security.validate_password(b.get("password"))
        if e: return err(e)
        if c.execute("SELECT 1 FROM users WHERE username=?", (un,)).fetchone(): return err("username already exists", 409)
        with tx(c):
            uid = c.execute("INSERT INTO users(username,display_name,role,password_hash,created_at) VALUES(?,?,?,?,?)", (un, txt(b.get("display_name"), 80) or un, b["role"], security.hash_pw(b["password"]), now_iso())).lastrowid
            audit.log(c, current_user(), "user.create", "user", uid, None, {"username": un, "role": b["role"]}, ip())
        return jsonify(id=uid), 201

    @app.patch("/api/users/<int:uid>")
    @require("users.manage")
    def user_update(uid):
        b = body(); c = get_db(); u = c.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u: return err("user not found", 404)
        me_ = current_user(); sets, vals, after = [], [], {}
        if "role" in b:
            if b["role"] not in ("admin", "analyst", "owner", "auditor"): return err("invalid role")
            sets.append("role=?"); vals.append(b["role"]); after["role"] = b["role"]
        if "active" in b: sets.append("active=?"); vals.append(int(bool(b["active"]))); after["active"] = bool(b["active"])
        if "display_name" in b: sets.append("display_name=?"); vals.append(txt(b["display_name"], 80)); after["display_name"] = txt(b["display_name"], 80)
        if b.get("password"):
            e = security.validate_password(b["password"])
            if e: return err(e)
            sets.append("password_hash=?"); vals.append(security.hash_pw(b["password"])); after["password"] = "reset"
        if not sets: return err("nothing to update")
        if uid == me_["id"] and (after.get("active") is False or ("role" in after and after["role"] != "admin")): return err("you cannot demote or deactivate your own account")
        with tx(c):
            c.execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", vals + [uid])
            if c.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND active=1").fetchone()[0] < 1: raise workflow.WorkflowError("at least one active admin is required", 409)
            audit.log(c, me_, "user.update", "user", uid, {"role": u["role"], "active": bool(u["active"])}, after, ip())
        return jsonify(ok=True)

    # ---------------- overview ----------------
    @app.get("/api/overview")
    @require("read")
    def overview():
        c = get_db(); today = db.today(); fs = data.query_findings(c, today=today)
        openf = [f for f in fs if f["status"] in UNRESOLVED]
        verified = sum(f["status"] == S_VERIFIED for f in fs); pending = [f for f in fs if f["status"] == S_FIXED]
        scans = [dict(r) for r in c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 5")]
        last_ok = c.execute("SELECT * FROM scans WHERE status='Complete' ORDER BY id DESC LIMIT 1").fetchone()
        sev = {s: sum(1 for f in openf if f["sev"] == s) for s in db.SEVERITIES}
        envs = {}
        for f in openf:
            e = envs.setdefault(f["environment"] or "Unassigned", {"environment": f["environment"] or "Unassigned", "open": 0, "critical_high": 0, "scores": []})
            e["open"] += 1; e["critical_high"] += f["sev"] in ("Critical", "High")
            if f["risk"]["score"] is not None: e["scores"].append(f["risk"]["score"])
        env_out = [{"environment": e["environment"], "open": e["open"], "critical_high": e["critical_high"], "avg_score": round(sum(e["scores"]) / len(e["scores"]), 1) if e["scores"] else None} for e in envs.values()]
        buckets = [("0-7d", 0, 7), ("8-30d", 8, 30), ("31-60d", 31, 60), ("61-90d", 61, 90), ("90d+", 91, 10**6)]
        aging = []
        for lab, lo, hi in buckets:
            n = 0
            for f in openf:
                age = (today - dt.datetime.fromisoformat(f["first_seen"]).date()).days
                n += lo <= age <= hi
            aging.append({"bucket": lab, "count": n})
        trend = []
        for wk in range(11, -1, -1):
            end = today - dt.timedelta(days=7 * wk); start = end - dt.timedelta(days=6)
            det = sum(start <= dt.datetime.fromisoformat(f["first_seen"]).date() <= end for f in fs)
            res = sum(1 for f in fs if f.get("verified_at") and f["status"] == S_VERIFIED and start <= dt.datetime.fromisoformat(f["verified_at"]).date() <= end)
            backlog = sum(1 for f in fs if dt.datetime.fromisoformat(f["first_seen"]).date() <= end and not (f.get("verified_at") and f["status"] == S_VERIFIED and dt.datetime.fromisoformat(f["verified_at"]).date() <= end))
            trend.append({"week": end.isoformat(), "new": det, "resolved": res, "open": backlog})
        queue = sorted([f for f in openf if f["status"] != S_FIXED], key=lambda f: -(f["risk"]["score"] or -1))[:8]
        due = sorted([f for f in openf if f["days_left"] is not None and 0 <= f["days_left"] <= 14], key=lambda f: f["days_left"])[:8]
        slim = lambda f: {k: f[k] for k in ("id", "name", "sev", "host", "port", "status", "due_date", "days_left", "overdue", "owner_name", "cve")} | {"risk": {k: f["risk"][k] for k in ("score", "category", "confidence", "provisional", "next_action")}}
        return jsonify(empty=(len(fs) == 0), metrics={
            "total_open": len(openf), "open_critical": sev["Critical"], "open_high": sev["High"], "affected_assets": len({f["asset_id"] for f in openf}),
            "overdue": sum(f["overdue"] for f in openf), "awaiting_verification": len(pending),
            "verified_rate": round(100 * verified / (verified + len(pending)), 1) if (verified + len(pending)) else None, "verified_count": verified,
            "latest_scan": dict(last_ok) if last_ok else None, "new_since_previous": (last_ok["new_count"] if last_ok else 0), "resolved_since_previous": (last_ok["resolved_count"] if last_ok else 0),
            "incomplete_assessments": sum(f["risk"]["category"] == "Incomplete" for f in openf), "risk_accepted": sum(f["status"] == S_ACCEPTED for f in fs)},
            severity=sev, by_environment=env_out, aging=aging, trend=trend, queue=[slim(f) for f in queue], upcoming=[slim(f) for f in due], recent_scans=scans)

    # ---------------- findings ----------------
    @app.get("/api/findings")
    @require("read")
    def findings_list():
        c = get_db(); a = request.args
        sort = a.get("sort", "risk"); sort = sort if sort in data.SORT_KEYS else "risk"; direction = "asc" if a.get("dir") == "asc" else "desc"
        if "page" not in a and "per_page" not in a:      # legacy contract: plain array
            rows = data.query_findings(c, finding_filters(), "cvss", "desc"); return jsonify(rows)
        rows = data.query_findings(c, finding_filters(), sort, direction); p, n = page_args()
        return jsonify(paginate(rows, p, n))

    @app.get("/api/findings/<fid>")
    @require("read")
    def finding_detail(fid):
        c = get_db(); rows = [r for r in data.query_findings(c, {"q": fid}, include_evidence=True) if r["id"] == fid]
        if not rows: return err("finding not found", 404)
        f = rows[0]; u = current_user()
        f["history"] = [dict(r) for r in c.execute("SELECT * FROM finding_history WHERE finding_id=? ORDER BY id DESC", (fid,))]
        f["audit"] = [dict(r) for r in c.execute("SELECT at,actor_name,action,before_json,after_json FROM audit_events WHERE object_type='finding' AND object_id=? ORDER BY id DESC LIMIT 50", (fid,))] if can(u, "audit.view") else None
        f["scans"] = [dict(r) for r in c.execute("SELECT s.id,s.source_type,s.filename,s.imported_at,s.status FROM sightings x JOIN scans s ON s.id=x.scan_id WHERE x.finding_id=? ORDER BY s.id DESC", (fid,))]
        f["first_scan"] = dict(c.execute("SELECT id,source_type,filename,imported_at,status FROM scans WHERE id=?", (f["first_scan_id"],)).fetchone() or {}) if f.get("first_scan_id") else None
        f["exceptions"] = [dict(r) for r in c.execute("SELECT * FROM exceptions WHERE finding_id=? ORDER BY id DESC", (fid,))]
        f["asset"] = asset_row(c, f["asset_id"])
        cves = [x.strip() for x in (f["cve"] or "").split(",") if x.strip()]
        f["cve_info"] = [{"cve": cv, "kev": (dict(k) if (k := c.execute("SELECT * FROM intel_kev WHERE cve=?", (cv,)).fetchone()) else None),
                          "reference": f"https://nvd.nist.gov/vuln/detail/{cv}", "note": "Lookup link only. Metadata is not fetched or asserted by this platform."} for cv in cves]
        rel = c.execute("""SELECT id,name,host,port,sev,status,'same asset, same CVE' reason FROM findings WHERE id!=? AND asset_id=? AND cve!='' AND cve=?
                           UNION SELECT id,name,host,port,sev,status,'same CVE on another asset' FROM findings WHERE id!=? AND cve!='' AND cve=? AND asset_id!=?
                           UNION SELECT id,name,host,port,sev,status,'possible duplicate (same asset and title)' FROM findings WHERE id!=? AND asset_id=? AND lower(name)=lower(?) LIMIT 20""",
                        (fid, f["asset_id"], f["cve"], fid, f["cve"], f["asset_id"], fid, f["asset_id"], f["name"])).fetchall()
        f["related"] = [dict(r) for r in rel]
        return jsonify(f)

    @app.post("/api/findings")
    @require("finding.create")
    def finding_create():
        b = body(); c = get_db(); u = current_user()
        host, name = txt(b.get("host"), 200), txt(b.get("name"), 300)
        if not host or not name: return err("host and title are required")
        port = txt(b.get("port"), 20) or "general"
        try: cv = float(b["cvss"]) if b.get("cvss") not in (None, "") else None
        except (TypeError, ValueError): return err("CVSS must be a number between 0 and 10")
        if cv is not None and not (0 <= cv <= 10): return err("CVSS must be between 0 and 10")
        sev = b.get("severity") if b.get("severity") in db.SEVERITIES else ("Critical" if (cv or 0) >= 9 else "High" if (cv or 0) >= 7 else "Medium" if (cv or 0) >= 4 else "Low" if (cv or 0) > 0 else "Info")
        cve = ", ".join(sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", (b.get("cve") or "").upper()))))
        import hashlib; ts = now_iso()
        with tx(c):
            aid = db.get_or_create_asset(c, host, "", ts); fp = db.fingerprint(db.asset_key(host), port, "Manual", db.vuln_key(name, cve))
            if c.execute("SELECT 1 FROM findings WHERE fingerprint=?", (fp,)).fetchone(): raise workflow.WorkflowError("an identical finding already exists", 409)
            fid = hashlib.sha1(f"{host}|{port}|{name}|manual".encode()).hexdigest()[:16]
            crit = c.execute("SELECT criticality FROM assets WHERE id=?", (aid,)).fetchone()[0]
            c.execute("""INSERT INTO findings(id,host,port,name,cvss,sev,rem,src,owasp,status,first_seen,updated,asset_id,fingerprint,cve,cvss_source,evidence,last_seen,due_date,exploit_status,manual,description)
                         VALUES(?,?,?,?,?,?,?,'Manual','-','Open',?,?,?,?,?,?,?,?,?,'Unknown',1,?)""",
                      (fid, host, port, name, cv or 0.0, sev, txt(b.get("remediation"), 1000) or "Define remediation.", ts, ts, aid, fp, cve, "Analyst-entered" if cv is not None else "None", txt(b.get("evidence"), 4000), ts, db.compute_due(c, ts, sev, crit), txt(b.get("description"), 2000)))
            workflow.history(c, fid, u, "detected", None, S_OPEN, "Created manually by analyst"); audit.log(c, u, "finding.create", "finding", fid, None, {"host": host, "name": name, "severity": sev}, ip())
        return jsonify(id=fid), 201

    @app.post("/api/findings/<fid>/transition")
    @require("read")
    def finding_transition(fid):
        b = body(); c = get_db(); u = current_user()
        if not can(u, "finding.status") and not can(u, "finding.status_own"): return err("you do not have permission to do this", 403)
        with tx(c): new = workflow.transition(c, fid, b.get("to"), u, txt(b.get("note"), 1000), txt(b.get("evidence"), 300), ip())
        return jsonify(status=new)

    @app.patch("/api/findings/<fid>")
    @require("read")
    def finding_legacy_patch(fid):          # legacy contract: {"status": "Open|In Progress|Fixed|Accepted Risk"}
        s = body().get("status"); c = get_db(); u = current_user()
        if s == "Accepted Risk": return err("risk acceptance now requires a justified, approved exception (Risk Exceptions page)", 400)
        s = {"Fixed": S_FIXED}.get(s, s)
        if s not in db.STATUSES: return err("invalid status")
        cur = c.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
        if cur and cur["status"] == s: return jsonify(ok=True)
        with tx(c): workflow.transition(c, fid, s, u, txt(body().get("note"), 1000) or "Updated via legacy API", "", ip())
        return jsonify(ok=True)

    @app.post("/api/findings/<fid>/assign")
    @require("finding.assign")
    def finding_assign(fid):
        b = body(); c = get_db(); u = current_user(); f = c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if not f: return err("finding not found", 404)
        oid = b.get("owner_id")
        if oid not in (None, ""):
            r = c.execute("SELECT role,active FROM users WHERE id=?", (oid,)).fetchone()
            if not r or not r["active"]: return err("owner not found")
        else: oid = None
        due = f["due_date"]
        if b.get("due_date"):
            d = parse_date(b["due_date"], "deadline"); due = d.isoformat()
        with tx(c):
            c.execute("UPDATE findings SET owner_id=?,due_date=?,updated=? WHERE id=?", (oid, due, now_iso(), fid))
            if oid != f["owner_id"]: workflow.history(c, fid, u, "assignment", str(f["owner_id"] or ""), str(oid or ""), txt(b.get("note"), 500))
            if due != f["due_date"]: workflow.history(c, fid, u, "deadline", f["due_date"], due, txt(b.get("note"), 500))
            audit.log(c, u, "finding.assign", "finding", fid, {"owner_id": f["owner_id"], "due_date": f["due_date"]}, {"owner_id": oid, "due_date": due}, ip())
        return jsonify(ok=True)

    @app.post("/api/findings/<fid>/note")
    @require("read")
    def finding_note(fid):
        b = body(); c = get_db(); u = current_user(); f = c.execute("SELECT owner_id FROM findings WHERE id=?", (fid,)).fetchone()
        if not f: return err("finding not found", 404)
        if not (can(u, "finding.note") or (u["role"] == "owner" and f["owner_id"] == u["id"])): return err("you do not have permission to do this", 403)
        n = txt(b.get("note"), 2000)
        if len(n) < 3: return err("note is too short")
        with tx(c): workflow.history(c, fid, u, "note", None, None, n, txt(b.get("evidence"), 300)); audit.log(c, u, "finding.note", "finding", fid, None, {"note": n[:200]}, ip())
        return jsonify(ok=True)

    @app.post("/api/findings/<fid>/exploit")
    @require("finding.exploit")
    def finding_exploit(fid):
        b = body(); c = get_db(); u = current_user(); f = c.execute("SELECT exploit_status FROM findings WHERE id=?", (fid,)).fetchone()
        if not f: return err("finding not found", 404)
        s = b.get("status")
        if s not in risk.EXPLOIT_VALUES: return err("invalid exploit status")
        ev = txt(b.get("evidence"), 1000)
        if s in ("Exploit confirmed (evidence)", "Public exploit reference", "None known") and len(ev) < 8: return err("an evidence reference or source is required for this determination")
        with tx(c):
            c.execute("UPDATE findings SET exploit_status=?,exploit_evidence=? WHERE id=?", (s, ev, fid))
            workflow.history(c, fid, u, "exploit", f["exploit_status"], s, ev); audit.log(c, u, "finding.exploit_status", "finding", fid, {"exploit_status": f["exploit_status"]}, {"exploit_status": s, "evidence": ev}, ip())
        return jsonify(ok=True)

    @app.delete("/api/findings")
    @require("*")
    def findings_clear():
        c = get_db(); u = current_user()
        if body().get("confirm") != "DELETE ALL FINDINGS": return err("send {\"confirm\": \"DELETE ALL FINDINGS\"} to confirm bulk deletion", 400)
        with tx(c):
            n = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            c.execute("DELETE FROM findings"); audit.log(c, u, "finding.bulk_delete", "finding", "*", {"count": n}, None, ip())
        return jsonify(ok=True, deleted=n)

    # ---------------- upload ----------------
    @app.post("/api/upload")
    @require("upload")
    @security.rate_limit("upload", 20, 60)
    def upload():
        c = get_db(); u = current_user(); files = request.files.getlist("files")
        if not files: return err("no files uploaded")
        if len(files) > 10: return err("at most 10 files per upload")
        partial = request.form.get("partial") in ("1", "true", "on"); extra = (request.form.get("covered_hosts") or "").replace("\n", ",").split(",")
        added, errors, results = 0, [], []
        for f in files:
            raw = f.read(); name = os.path.basename(f.filename or "upload")
            try:
                parsed = parse_report(name, raw)
                with tx(c): res = workflow.ingest_scan(c, parsed, name, raw, u, partial, extra[:200], txt(request.form.get("notes"), 500), ip())
                added += res["new"]; results.append(res)
            except (ReportError, workflow.WorkflowError) as e:
                errors.append(f"{name}: {e}")
                with tx(c): workflow.record_failed_scan(c, name, raw, u, str(e), ip())
        return jsonify(added=added, errors=errors, scans=results), (200 if results or not errors else 422)

    # ---------------- scans ----------------
    @app.get("/api/scans")
    @require("read")
    def scans():
        c = get_db()
        rows = [dict(r) | {"assets": c.execute("SELECT COUNT(*) FROM scan_assets WHERE scan_id=?", (r["id"],)).fetchone()[0],
                           "imported_by_name": (c.execute("SELECT username FROM users WHERE id=?", (r["imported_by"],)).fetchone() or [None])[0]} for r in c.execute("SELECT * FROM scans ORDER BY id DESC")]
        return jsonify(rows)

    @app.get("/api/scans/<int:sid>")
    @require("read")
    def scan_detail(sid):
        c = get_db(); s = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
        if not s: return err("scan not found", 404)
        a = [dict(r) for r in c.execute("SELECT a.id,a.asset_key,a.environment FROM scan_assets x JOIN assets a ON a.id=x.asset_id WHERE x.scan_id=?", (sid,))]
        prev = c.execute("SELECT id FROM scans WHERE id<? AND source_type=? AND status!='Failed' ORDER BY id DESC LIMIT 1", (sid, s["source_type"])).fetchone()
        return jsonify(dict(s) | {"assets": a, "previous_id": prev[0] if prev else None})

    @app.get("/api/scans/compare")
    @require("read")
    def scans_compare():
        a, b = request.args.get("a", ""), request.args.get("b", "")
        if not (a.isdigit() and b.isdigit()): return err("a and b scan ids are required")
        return jsonify(workflow.compare_scans(get_db(), int(a), int(b)))

    # ---------------- assets ----------------
    @app.get("/api/assets")
    @require("read")
    def assets():
        c = get_db(); rows = data.asset_summary(c); a = request.args
        if a.get("environment"): rows = [r for r in rows if r["environment"] == a["environment"]]
        if a.get("q"): rows = [r for r in rows if a["q"].lower() in (r["asset_key"] + r["hostname"]).lower()]
        rows.sort(key=lambda r: -r["overall_risk"]); return jsonify(rows)

    @app.get("/api/assets/<int:aid>")
    @require("read")
    def asset_detail(aid):
        c = get_db(); r = [x for x in data.asset_summary(c) if x["id"] == aid]
        if not r: return err("asset not found", 404)
        fs = data.query_findings(c, {"asset": aid})
        hist = [dict(x) for x in c.execute("SELECT s.id,s.imported_at,s.source_type,s.status,(SELECT COUNT(*) FROM sightings k WHERE k.scan_id=s.id AND k.finding_id IN (SELECT id FROM findings WHERE asset_id=?)) n FROM scan_assets x JOIN scans s ON s.id=x.scan_id WHERE x.asset_id=? ORDER BY s.id DESC", (aid, aid))]
        return jsonify(asset=r[0], findings=fs, scan_history=hist)

    @app.patch("/api/assets/<int:aid>")
    @require("asset.edit")
    def asset_update(aid):
        b = body(); c = get_db(); a = asset_row(c, aid)
        if not a: return err("asset not found", 404)
        allowed = {"environment": db.ENVIRONMENTS, "criticality": db.CRITICALITY, "internet_exposure": ["Internet-facing", "Internal", "Unknown"],
                   "business_importance": ["Mission-critical", "Important", "Supporting", "Unrated"]}
        sets, vals, after = [], [], {}
        for k, ok in allowed.items():
            if k in b:
                if b[k] not in ok: return err(f"invalid {k}")
                sets.append(f"{k}=?"); vals.append(b[k]); after[k] = b[k]
        if "owner_id" in b:
            if b["owner_id"] not in (None, "") and not c.execute("SELECT 1 FROM users WHERE id=? AND active=1", (b["owner_id"],)).fetchone(): return err("owner not found")
            after["owner_id"] = b["owner_id"] or None; sets.append("owner_id=?"); vals.append(after["owner_id"])
        if "notes" in b: sets.append("notes=?"); vals.append(txt(b["notes"], 1000)); after["notes"] = txt(b["notes"], 1000)
        if "internet_exposure" in after:
            src = txt(b.get("exposure_source"), 200)
            if after["internet_exposure"] != "Unknown" and len(src) < 3: return err("state the source of the exposure determination (e.g. 'external scan', 'firewall rule review')")
            sets.append("exposure_source=?"); vals.append(src if after["internet_exposure"] != "Unknown" else ""); after["exposure_source"] = src
        if not sets: return err("nothing to update")
        sets.append("updated_at=?"); vals.append(now_iso())
        with tx(c):
            c.execute(f"UPDATE assets SET {','.join(sets)} WHERE id=?", vals + [aid])
            if "criticality" in after and after["criticality"] != a["criticality"]:   # SLA windows depend on asset criticality
                for f in c.execute("SELECT id,sev,first_seen FROM findings WHERE asset_id=? AND status IN (?,?,?,?,?)", (aid, *UNRESOLVED)).fetchall():
                    nd = db.compute_due(c, f["first_seen"], f["sev"], after["criticality"])
                    c.execute("UPDATE findings SET due_date=? WHERE id=?", (nd, f["id"]))
            audit.log(c, current_user(), "asset.update", "asset", aid, {k: a[k] for k in after if k in a}, after, ip())
        return jsonify(ok=True)

    # ---------------- attack paths ----------------
    @app.get("/api/graph")
    @require("read")
    def graph():
        c = get_db(); am = {a["id"]: a for a in data.asset_summary(c)}; fs = data.query_findings(c, {"status": "open"})
        nodes, edges = [], []
        for a in am.values():
            why = [f"Asset seen in scan #{a['last_scan_id']}" if a["last_scan_id"] else "Asset record"]
            if a["open_findings"]: why.append(f"{a['open_findings']} open finding(s); highest severity {a['highest_severity']}")
            if a["internet_exposure"] == "Internet-facing": why.append(f"Internet-facing ({a['exposure_source'] or 'source not stated'})")
            nodes.append({"id": f"a{a['id']}", "type": "asset", "label": a["asset_key"], "env": a["environment"], "risk": a["overall_risk"], "criticality": a["criticality"], "exposure": a["internet_exposure"],
                          "open": a["open_findings"], "why": why, "asset_id": a["id"], "high_risk": a["overall_risk"] >= 55 or a["highest_severity"] in ("Critical",)})
        svc = {}
        for f in fs:
            k = (f["asset_id"], f["port"])
            s = svc.setdefault(k, {"asset": f["asset_id"], "port": f["port"], "sev": f["sev"], "names": [], "scan": f["last_scan_id"], "max": 0})
            s["names"].append(f["name"]); s["max"] = max(s["max"], f["risk"]["score"] or 0)
            if db.SEVERITIES.index(f["sev"]) < db.SEVERITIES.index(s["sev"]): s["sev"] = f["sev"]
        for (aid, port), s in svc.items():
            if aid not in am: continue
            sid = f"s{aid}-{port}"
            nodes.append({"id": sid, "type": "service", "label": port, "risk": s["max"], "sev": s["sev"], "open": len(s["names"]), "high_risk": s["sev"] in ("Critical", "High"),
                          "why": [f"Observed in scan #{s['scan']}: {n}" for n in s["names"][:4]]})
            edges.append({"from": f"a{aid}", "to": sid, "kind": "observed", "label": "hosts service", "evidence": f"scan #{s['scan']}"})
        for r in c.execute("SELECT * FROM relationships"):
            edges.append({"id": r["id"], "from": f"a{r['src_asset_id']}", "to": f"a{r['dst_asset_id']}", "kind": r["kind"], "label": r["label"] or "can reach", "evidence": r["evidence"] or "", "removable": True})
        subnets = {}
        for a in am.values():
            m = re.match(r"^(\d+\.\d+\.\d+)\.\d+$", a["ip"] or "")
            if m: subnets.setdefault(m.group(1), []).append(a["id"])
        for pre, ids in subnets.items():
            if len(ids) < 2: continue
            nid = f"n{pre}"; nodes.append({"id": nid, "type": "network", "label": f"{pre}.0/24", "risk": 0, "open": 0, "high_risk": False, "why": ["Inferred grouping from IPv4 addresses. Shows address adjacency only, NOT proven connectivity."]})
            for i in ids: edges.append({"from": f"a{i}", "to": nid, "kind": "inferred", "label": "same /24 (inferred)", "evidence": "address prefix"})
        adj = {}
        for e in edges:
            if e["kind"] in ("manual", "observed") and e["from"].startswith("a") and e["to"].startswith("a"): adj.setdefault(e["from"], []).append(e["to"])
        paths = []
        entries = [f"a{a['id']}" for a in am.values() if a["internet_exposure"] == "Internet-facing"]
        targets = {f"a{a['id']}" for a in am.values() if a["criticality"] in ("Critical", "High") or a["overall_risk"] >= 55}
        for s in entries:
            q = [[s]]
            while q:
                p = q.pop(0)
                if len(p) > 1 and p[-1] in targets: paths.append(p)
                if len(p) < 5:
                    for n in adj.get(p[-1], []):
                        if n not in p: q.append(p + [n])
        label = {n["id"]: n["label"] for n in nodes}
        return jsonify(nodes=nodes, edges=edges, paths=[{"nodes": p, "labels": [label[x] for x in p], "status": "Unverified hypothesis built from manual/observed relationships. No exploitation has been demonstrated."} for p in paths[:20]],
                       legend={"observed": "Seen in imported scan data", "manual": "Entered by an analyst (lab/assumed relationship)", "inferred": "Derived grouping; not evidence of connectivity"})

    @app.post("/api/relationships")
    @require("relationship.edit")
    def rel_create():
        b = body(); c = get_db(); u = current_user()
        try: s, d = int(b.get("src")), int(b.get("dst"))
        except (TypeError, ValueError): return err("src and dst asset ids are required")
        if s == d: return err("source and destination must differ")
        if not (asset_row(c, s) and asset_row(c, d)): return err("asset not found", 404)
        label = txt(b.get("label"), 80) or "can reach"; ev = txt(b.get("evidence"), 300)
        if len(ev) < 5: return err("state why this relationship is believed (lab note, network diagram reference, etc.)")
        with tx(c):
            rid = c.execute("INSERT INTO relationships(src_asset_id,dst_asset_id,label,kind,evidence,created_by,created_at) VALUES(?,?,?,'manual',?,?,?)", (s, d, label, ev, u["id"], now_iso())).lastrowid
            audit.log(c, u, "relationship.create", "relationship", rid, None, {"src": s, "dst": d, "label": label, "kind": "manual"}, ip())
        return jsonify(id=rid), 201

    @app.delete("/api/relationships/<int:rid>")
    @require("relationship.edit")
    def rel_delete(rid):
        c = get_db(); r = c.execute("SELECT * FROM relationships WHERE id=?", (rid,)).fetchone()
        if not r: return err("relationship not found", 404)
        with tx(c): c.execute("DELETE FROM relationships WHERE id=?", (rid,)); audit.log(c, current_user(), "relationship.delete", "relationship", rid, dict(r), None, ip())
        return jsonify(ok=True)

    # ---------------- remediation / SLA ----------------
    @app.get("/api/remediation")
    @require("read")
    def remediation():
        c = get_db(); fs = data.query_findings(c, {"status": "open"})
        slim = lambda f: {k: f[k] for k in ("id", "name", "sev", "host", "port", "status", "due_date", "days_left", "owner_id", "owner_name", "fixed_at")} | {"score": f["risk"]["score"], "category": f["risk"]["category"], "next_action": f["risk"]["next_action"]}
        exp = [dict(r) for r in c.execute("SELECT e.id,e.finding_id,e.expires_at,f.name,f.host,f.sev FROM exceptions e JOIN findings f ON f.id=e.finding_id WHERE e.status='Approved' AND e.expires_at<=?", ((db.today() + dt.timedelta(days=14)).isoformat(),))]
        rr = [dict(r) for r in c.execute("SELECT e.id,e.finding_id,e.expires_at,f.name,f.host,f.sev FROM exceptions e JOIN findings f ON f.id=e.finding_id WHERE e.status='Re-review required'")]
        return jsonify(overdue=[slim(f) for f in sorted((f for f in fs if f["overdue"]), key=lambda f: f["days_left"])],
                       due_soon=[slim(f) for f in sorted((f for f in fs if f["days_left"] is not None and 0 <= f["days_left"] <= 7), key=lambda f: f["days_left"])],
                       unassigned_critical=[slim(f) for f in fs if not f["owner_id"] and (f["sev"] in ("Critical", "High") or f["risk"]["category"] in ("Critical", "High"))],
                       awaiting_verification=[slim(f) for f in fs if f["status"] == S_FIXED], expiring_exceptions=exp, re_review=rr,
                       board={s: [slim(f) for f in fs if f["status"] == s][:50] for s in (S_OPEN, "Triaged", "In Progress", S_FIXED, S_REOPENED)},
                       note="This is a rule-based SLA risk forecast / remediation queue. No predictive model is used.")

    # ---------------- exceptions ----------------
    @app.get("/api/exceptions")
    @require("read")
    def exceptions():
        c = get_db(); q = """SELECT e.*, f.name finding_name, f.host, f.sev, COALESCE(r.display_name,r.username) requester, COALESCE(a.display_name,a.username) approver FROM exceptions e
                             JOIN findings f ON f.id=e.finding_id LEFT JOIN users r ON r.id=e.requested_by LEFT JOIN users a ON a.id=e.approver_id"""
        st = request.args.get("status")
        rows = c.execute(q + (" WHERE e.status=?" if st else "") + " ORDER BY e.id DESC", ((st,) if st else ())).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.post("/api/exceptions")
    @require("exception.request")
    def exception_create():
        b = body(); c = get_db(); u = current_user(); f = c.execute("SELECT * FROM findings WHERE id=?", (b.get("finding_id"),)).fetchone()
        if not f: return err("finding not found", 404)
        if u["role"] == "owner" and f["owner_id"] != u["id"]: return err("you can only request exceptions for findings assigned to you", 403)
        if f["status"] in (S_VERIFIED, S_ACCEPTED): return err(f"a finding that is '{f['status']}' cannot take a new exception")
        j, cc = txt(b.get("justification"), 3000), txt(b.get("compensating_controls"), 3000)
        if len(j) < 20: return err("business justification must be at least 20 characters")
        if len(cc) < 10: return err("describe the compensating controls (min 10 characters)")
        exp = parse_date(b.get("expires_at"), "expiry date")
        if not (db.today() < exp <= db.today() + dt.timedelta(days=365)): return err("expiry must be in the future and within 365 days")
        if c.execute("SELECT 1 FROM exceptions WHERE finding_id=? AND status IN ('Pending','Approved','Re-review required')", (f["id"],)).fetchone(): return err("an active exception already exists for this finding", 409)
        with tx(c):
            eid = c.execute("INSERT INTO exceptions(finding_id,requested_by,requested_at,justification,compensating_controls,status,expires_at) VALUES(?,?,?,?,?,'Pending',?)", (f["id"], u["id"], now_iso(), j, cc, exp.isoformat())).lastrowid
            workflow.history(c, f["id"], u, "exception", None, "Pending", f"Risk exception #{eid} requested (expires {exp})"); audit.log(c, u, "exception.request", "exception", eid, None, {"finding": f["id"], "expires_at": exp.isoformat()}, ip())
        return jsonify(id=eid), 201

    def _exc(c, eid):
        e = c.execute("SELECT * FROM exceptions WHERE id=?", (eid,)).fetchone()
        if not e: raise workflow.WorkflowError("exception not found", 404)
        return e

    @app.post("/api/exceptions/<int:eid>/approve")
    @require("exception.approve")
    def exception_approve(eid):
        b = body(); c = get_db(); u = current_user(); e = _exc(c, eid)
        if e["status"] not in ("Pending", "Re-review required"): return err(f"exception is {e['status']}", 409)
        if e["requested_by"] == u["id"]: return err("you cannot approve your own exception request", 403)
        exp = parse_date(b.get("expires_at") or e["expires_at"], "expiry date")
        if not (db.today() < exp <= db.today() + dt.timedelta(days=365)): return err("expiry must be in the future and within 365 days (set a new expiry when renewing)")
        note = txt(b.get("note"), 500)
        if e["status"] == "Re-review required" and len(note) < 10: return err("a review note is required when renewing an expired exception")
        with tx(c):
            c.execute("UPDATE exceptions SET status='Approved',approver_id=?,approved_at=?,expires_at=?,review_note=? WHERE id=?", (u["id"], now_iso(), exp.isoformat(), note, eid))
            f = c.execute("SELECT status FROM findings WHERE id=?", (e["finding_id"],)).fetchone()
            c.execute("UPDATE findings SET status=?,updated=? WHERE id=?", (S_ACCEPTED, now_iso(), e["finding_id"]))
            workflow.history(c, e["finding_id"], u, "status", f["status"], S_ACCEPTED, f"Exception #{eid} approved until {exp}. NOT a fix; risk remains.", f"exception:{eid}")
            audit.log(c, u, "exception.approve", "exception", eid, {"status": e["status"]}, {"status": "Approved", "expires_at": exp.isoformat()}, ip())
        return jsonify(ok=True)

    @app.post("/api/exceptions/<int:eid>/reject")
    @require("exception.approve")
    def exception_reject(eid):
        b = body(); c = get_db(); u = current_user(); e = _exc(c, eid); note = txt(b.get("note"), 500)
        if e["status"] not in ("Pending", "Re-review required", "Approved"): return err(f"exception is {e['status']}", 409)
        if len(note) < 10: return err("a reason is required (min 10 characters)")
        new = "Revoked" if e["status"] == "Approved" else "Rejected"
        with tx(c):
            c.execute("UPDATE exceptions SET status=?,approver_id=?,review_note=? WHERE id=?", (new, u["id"], note, eid))
            f = c.execute("SELECT status FROM findings WHERE id=?", (e["finding_id"],)).fetchone()
            if f["status"] == S_ACCEPTED:
                c.execute("UPDATE findings SET status=?,reopen_count=COALESCE(reopen_count,0)+1,updated=? WHERE id=?", (S_REOPENED, now_iso(), e["finding_id"]))
                workflow.history(c, e["finding_id"], u, "status", S_ACCEPTED, S_REOPENED, f"Exception #{eid} revoked: {note}")
            audit.log(c, u, "exception." + new.lower(), "exception", eid, {"status": e["status"]}, {"status": new, "note": note}, ip())
        return jsonify(ok=True)

    # ---------------- reports / exports ----------------
    @app.get("/api/reports/<name>.<fmt>")
    @require("export")
    @security.rate_limit("report", 30, 60)
    def report(name, fmt):
        if fmt not in ("csv", "pdf"): return err("format must be csv or pdf")
        c = get_db(); u = current_user()
        try: rep = reports.build(c, name, request.args, u)
        except KeyError: return err("unknown report", 404)
        out = reports.to_csv(rep) if fmt == "csv" else reports.to_pdf(rep)
        with tx(c): audit.log(c, u, "report.export", "report", name, None, {"format": fmt, "filters": rep["meta"]["filters"], "rows": len(rep["rows"])}, ip())
        return Response(out, mimetype="text/csv; charset=utf-8" if fmt == "csv" else "application/pdf", headers={"Content-Disposition": f"attachment; filename=vulntrack_{name}.{fmt}"})

    @app.get("/api/reports")
    @require("export")
    def report_list():
        return jsonify([{"id": i, "title": t, "desc": d} for i, t, d in (
            ("inventory", "Vulnerability inventory", "Every finding with CVSS, internal priority, owner and SLA. Respects filters."),
            ("critical-high", "Critical & high-risk findings", "Open items rated Critical/High by CVSS severity or internal priority, with reasoning."),
            ("asset-risk", "Asset risk", "Per-asset open findings, highest severity and overall internal risk."),
            ("sla-breaches", "SLA breaches", "Overdue open findings and days overdue."),
            ("remediation-performance", "Remediation performance", "Verified fixes, time-to-fix and SLA attainment. Unverified fixes are not counted."),
            ("scan-comparison", "Scan-to-scan comparison", "New, persistent, resolved, recurring and reopened findings between two scans."),
            ("exceptions", "Risk acceptance exceptions", "Justification, approver, expiry and review state."))])

    @app.get("/api/export.csv")
    @require("export")
    def legacy_export():
        c = get_db(); u = current_user(); b = io.StringIO(); import csv; w = csv.writer(b)
        w.writerow(["Severity", "CVSS", "Host", "Port", "Finding", "OWASP", "Remediation", "Status", "Source", "First seen", "Updated"])
        for r in data.query_findings(c, {}, "cvss", "desc"): w.writerow([reports.safe_cell(x) for x in (r["sev"], r["cvss"], r["host"], r["port"], r["name"], r["owasp"], r["rem"], r["status"], r["src"], r["first_seen"], r["updated"])])
        with tx(c): audit.log(c, u, "report.export", "report", "legacy-export", None, {"format": "csv"}, ip())
        return Response(b.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=vulnerability_tracker.csv"})

    # ---------------- audit ----------------
    @app.get("/api/audit")
    @require("audit.view")
    def audit_list():
        c = get_db(); a = request.args; w, p = [], []
        for k, col in (("action", "action"), ("actor", "actor_name"), ("object_type", "object_type")):
            if a.get(k): w.append(f"{col}=?"); p.append(a[k])
        if a.get("q"): w.append("(object_id LIKE ? OR action LIKE ? OR actor_name LIKE ?)"); p += ["%" + a["q"].replace("%", "") + "%"] * 3
        pg, n = page_args(50)
        tot = c.execute("SELECT COUNT(*) FROM audit_events" + (" WHERE " + " AND ".join(w) if w else ""), p).fetchone()[0]
        rows = [dict(r) for r in c.execute("SELECT id,at,actor_name,role,action,object_type,object_id,before_json,after_json,ip FROM audit_events" + (" WHERE " + " AND ".join(w) if w else "") + " ORDER BY id DESC LIMIT ? OFFSET ?", p + [n, (pg - 1) * n])]
        acts = [r[0] for r in c.execute("SELECT DISTINCT action FROM audit_events ORDER BY action")]
        return jsonify({"items": rows, "total": tot, "page": pg, "per_page": n, "pages": max(1, -(-tot // n)), "actions": acts})

    @app.get("/api/audit/verify")
    @require("audit.view")
    def audit_verify():
        return jsonify(audit.verify_chain(get_db()) | {"note": "Detects accidental or naive tampering only; a SQLite file is not cryptographically immutable."})

    # ---------------- search / activity ----------------
    @app.get("/api/search")
    @require("read")
    def search():
        q = txt(request.args.get("q"), 80); c = get_db()
        if len(q) < 2: return jsonify(findings=[], assets=[])
        fs = data.query_findings(c, {"q": q}, "risk", "desc")[:6]
        like = "%" + q.replace("%", "") + "%"
        a = [dict(r) for r in c.execute("SELECT id,asset_key,hostname,environment FROM assets WHERE asset_key LIKE ? OR hostname LIKE ? LIMIT 6", (like, like))]
        return jsonify(findings=[{k: f[k] for k in ("id", "name", "sev", "host", "cve", "status")} for f in fs], assets=a)

    @app.get("/api/activity")
    @require("read")
    def activity():
        c = get_db()
        h = [dict(r) for r in c.execute("SELECT h.at,h.actor_name,h.kind,h.to_value,h.note,h.finding_id,f.name FROM finding_history h JOIN findings f ON f.id=h.finding_id WHERE h.kind!='detected' ORDER BY h.id DESC LIMIT 12")]
        s = [dict(r) for r in c.execute("SELECT id,imported_at,source_type,status,parsed_count FROM scans ORDER BY id DESC LIMIT 5")]
        return jsonify(history=h, scans=s)

    # ---------------- settings / intel ----------------
    @app.get("/api/settings")
    @require("read")
    def settings_get():
        c = get_db(); k = c.execute("SELECT COUNT(*), MAX(imported_at) FROM intel_kev").fetchone()
        return jsonify(weights=data.weights(c), default_weights=risk.DEFAULT_WEIGHTS, thresholds=[{"min": t, "category": n} for t, n in risk.THRESH],
                       policies=[dict(r) for r in c.execute("SELECT * FROM policies ORDER BY severity,criticality")], kev={"count": k[0], "last_import": k[1]},
                       demo=current_app.config["DEMO_MODE"], env=current_app.config["ENV"], severities=db.SEVERITIES, criticality=db.CRITICALITY)

    @app.put("/api/settings/weights")
    @require("*")
    def weights_put():
        b = body(); c = get_db(); new = {}
        for k in risk.DEFAULT_WEIGHTS:
            try: v = float(b.get(k))
            except (TypeError, ValueError): return err(f"weight '{k}' must be a number")
            if not (0 <= v <= 1): return err(f"weight '{k}' must be between 0 and 1")
            new[k] = v
        if sum(new.values()) <= 0: return err("at least one weight must be positive")
        with tx(c): old = data.weights(c); db.set_setting(c, "risk_weights", new); audit.log(c, current_user(), "settings.weights", "settings", "risk_weights", old, new, ip())
        return jsonify(ok=True)

    @app.put("/api/settings/policies")
    @require("*")
    def policies_put():
        rows = body().get("policies"); c = get_db()
        if not isinstance(rows, list) or not rows: return err("policies list required")
        for r in rows:
            if r.get("severity") not in db.SEVERITIES or r.get("criticality") not in db.CRITICALITY or not isinstance(r.get("days"), int) or not (1 <= r["days"] <= 730): return err("each policy needs severity, criticality and days (1-730)")
        with tx(c):
            for r in rows: c.execute("UPDATE policies SET days=? WHERE severity=? AND criticality=?", (r["days"], r["severity"], r["criticality"]))
            audit.log(c, current_user(), "settings.policies", "settings", "policies", None, {"updated": len(rows)}, ip())
        return jsonify(ok=True)

    @app.post("/api/intel/kev")
    @require("*")
    @security.rate_limit("kev", 10, 60)
    def kev_import():
        f = request.files.get("file"); c = get_db()
        if not f: return err("no file uploaded")
        raw = f.read()
        if len(raw) > 10 * 1024 * 1024: return err("file too large")
        try:
            txt_ = raw.decode("utf-8-sig"); ent = []
            if f.filename.lower().endswith(".json"):
                for v in json.loads(txt_)["vulnerabilities"]: ent.append((v["cveID"], v.get("vendorProject", ""), v.get("product", ""), v.get("vulnerabilityName", ""), v.get("dateAdded", "")))
            else:
                import csv
                for r in csv.DictReader(io.StringIO(txt_)): ent.append((r["cveID"], r.get("vendorProject", ""), r.get("product", ""), r.get("vulnerabilityName", ""), r.get("dateAdded", "")))
            ent = [e for e in ent if re.match(r"^CVE-\d{4}-\d{4,7}$", e[0])]
        except Exception: return err("could not read file: expected the CISA KEV catalogue in JSON or CSV format")
        if not ent: return err("no valid CVE entries found")
        with tx(c):
            for e in ent: c.execute("INSERT OR REPLACE INTO intel_kev VALUES(?,?,?,?,?,?,?)", (*e, "User-imported KEV catalogue", now_iso()))
            audit.log(c, current_user(), "intel.kev_import", "intel", "kev", None, {"entries": len(ent), "file": f.filename}, ip())
        return jsonify(imported=len(ent))

if not os.environ.get("VULNTRACK_NO_AUTOAPP"): app = create_app()
if __name__ == "__main__": app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 8000)))
