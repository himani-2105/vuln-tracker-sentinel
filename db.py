"""SQLite access + additive, idempotent migrations. Never drops or resets data."""
import os, re, json, shutil, sqlite3, hashlib, datetime as dt
from contextlib import contextmanager
SCHEMA_VERSION = 3
S_OPEN, S_TRIAGED, S_PROG, S_FIXED, S_VERIFIED, S_ACCEPTED, S_REOPENED = (
    "Open", "Triaged", "In Progress", "Fixed — Pending Verification", "Verified Resolved", "Risk Accepted", "Reopened")
STATUSES = [S_OPEN, S_TRIAGED, S_PROG, S_FIXED, S_VERIFIED, S_ACCEPTED, S_REOPENED]
UNRESOLVED = [S_OPEN, S_TRIAGED, S_PROG, S_FIXED, S_REOPENED]   # still counted as open exposure
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
ENVIRONMENTS = ["Production", "Staging", "Development", "Lab", "Unassigned"]
CRITICALITY = ["Critical", "High", "Medium", "Low", "Unrated"]

def utcnow(): return dt.datetime.now(dt.timezone.utc)
def now_iso(): return utcnow().isoformat(timespec="seconds")
def today(): return utcnow().date()

def connect(path):
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    c = sqlite3.connect(path, timeout=10, isolation_level=None)  # explicit transactions via tx()
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON"); c.execute("PRAGMA busy_timeout=8000")
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA synchronous=NORMAL")
    return c

@contextmanager
def tx(c):
    c.execute("BEGIN IMMEDIATE")
    try:
        yield c; c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK"); raise

# ---------- identity helpers (stable matching) ----------
def asset_key(host, hostname=""):
    return (host or hostname or "unknown").strip().lower()
def split_port(p):
    m = re.match(r"^(\d+)/(\w+)$", p or "")
    return (int(m.group(1)), m.group(2)) if m else (None, None)
def vuln_key(name, cve):
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", (cve or "").upper())))
    if cves: return "|".join(cves)
    return re.sub(r"\s*\(.*?\)\s*$", "", (name or "").strip().lower())
def fingerprint(akey, port, src, vkey):
    """asset identity + service/port + source family + vulnerability identifier"""
    return hashlib.sha256(f"{akey}|{port or ''}|{src}|{vkey}".encode()).hexdigest()[:32]

DEFAULT_SLA_DAYS = {"Critical": 7, "High": 30, "Medium": 60, "Low": 90, "Info": 180}
CRIT_FACTOR = {"Critical": 0.5, "High": 0.75, "Medium": 1.0, "Low": 1.5, "Unrated": 1.0}

DDL = """
CREATE TABLE IF NOT EXISTS findings(id TEXT PRIMARY KEY,host TEXT,port TEXT,name TEXT,cvss REAL,sev TEXT,rem TEXT,src TEXT,owasp TEXT,status TEXT DEFAULT 'Open',first_seen TEXT,updated TEXT);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT,
  role TEXT NOT NULL CHECK(role IN('admin','analyst','owner','auditor')), password_hash TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at TEXT, last_login TEXT);
CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY AUTOINCREMENT, asset_key TEXT NOT NULL UNIQUE, hostname TEXT, ip TEXT,
  environment TEXT NOT NULL DEFAULT 'Unassigned', owner_id INTEGER REFERENCES users(id), criticality TEXT NOT NULL DEFAULT 'Unrated',
  business_importance TEXT NOT NULL DEFAULT 'Unrated', internet_exposure TEXT NOT NULL DEFAULT 'Unknown', exposure_source TEXT,
  notes TEXT, first_seen TEXT, last_scan_id INTEGER, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, source_type TEXT NOT NULL, filename TEXT, sha256 TEXT, imported_at TEXT NOT NULL,
  imported_by INTEGER REFERENCES users(id), status TEXT NOT NULL CHECK(status IN('Complete','Partial','Failed')), parsed_count INTEGER DEFAULT 0,
  rejected_count INTEGER DEFAULT 0, new_count INTEGER DEFAULT 0, resolved_count INTEGER DEFAULT 0, notes TEXT, error TEXT);
CREATE TABLE IF NOT EXISTS scan_assets(scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, asset_id INTEGER NOT NULL REFERENCES assets(id), PRIMARY KEY(scan_id,asset_id));
CREATE TABLE IF NOT EXISTS sightings(scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, PRIMARY KEY(scan_id,finding_id));
CREATE TABLE IF NOT EXISTS finding_history(id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, at TEXT NOT NULL,
  actor_id INTEGER, actor_name TEXT, kind TEXT NOT NULL, from_value TEXT, to_value TEXT, note TEXT, evidence_ref TEXT);
CREATE TABLE IF NOT EXISTS exceptions(id INTEGER PRIMARY KEY AUTOINCREMENT, finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE, requested_by INTEGER REFERENCES users(id),
  requested_at TEXT, justification TEXT NOT NULL, compensating_controls TEXT, status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN('Pending','Approved','Rejected','Re-review required','Revoked')),
  approver_id INTEGER REFERENCES users(id), approved_at TEXT, expires_at TEXT, review_note TEXT);
CREATE TABLE IF NOT EXISTS policies(severity TEXT NOT NULL, criticality TEXT NOT NULL, days INTEGER NOT NULL CHECK(days>0), PRIMARY KEY(severity,criticality));
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS intel_kev(cve TEXT PRIMARY KEY, vendor TEXT, product TEXT, name TEXT, date_added TEXT, source TEXT, imported_at TEXT);
CREATE TABLE IF NOT EXISTS relationships(id INTEGER PRIMARY KEY AUTOINCREMENT, src_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  dst_asset_id INTEGER NOT NULL REFERENCES assets(id) ON DELETE CASCADE, label TEXT, kind TEXT NOT NULL CHECK(kind IN('manual','observed')), evidence TEXT, created_by INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS audit_events(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor_id INTEGER, actor_name TEXT, role TEXT, action TEXT NOT NULL,
  object_type TEXT, object_id TEXT, before_json TEXT, after_json TEXT, ip TEXT, prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, username TEXT, ip TEXT, success INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events BEGIN SELECT RAISE(ABORT,'audit_events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events BEGIN SELECT RAISE(ABORT,'audit_events is append-only'); END;
"""
NEW_FINDING_COLS = {  # ALTER TABLE ADD COLUMN, only if missing
 "asset_id": "INTEGER REFERENCES assets(id)", "fingerprint": "TEXT", "cve": "TEXT", "cvss_source": "TEXT", "cvss_vector": "TEXT", "service": "TEXT",
 "evidence": "TEXT", "last_seen": "TEXT", "first_scan_id": "INTEGER", "last_scan_id": "INTEGER", "owner_id": "INTEGER REFERENCES users(id)", "due_date": "TEXT",
 "exploit_status": "TEXT DEFAULT 'Unknown'", "exploit_evidence": "TEXT", "fixed_at": "TEXT", "fixed_by": "INTEGER", "verified_at": "TEXT", "verified_by": "INTEGER",
 "verification_method": "TEXT", "verification_scan_id": "INTEGER", "reopen_count": "INTEGER DEFAULT 0", "description": "TEXT", "refs": "TEXT", "manual": "INTEGER DEFAULT 0"}
INDEXES = """CREATE INDEX IF NOT EXISTS ix_f_asset ON findings(asset_id); CREATE INDEX IF NOT EXISTS ix_f_status ON findings(status);
CREATE INDEX IF NOT EXISTS ix_f_sev ON findings(sev); CREATE INDEX IF NOT EXISTS ix_f_due ON findings(due_date); CREATE UNIQUE INDEX IF NOT EXISTS ux_f_fp ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS ix_f_cve ON findings(cve); CREATE INDEX IF NOT EXISTS ix_hist_f ON finding_history(finding_id); CREATE INDEX IF NOT EXISTS ix_sight_f ON sightings(finding_id);
CREATE INDEX IF NOT EXISTS ix_audit_at ON audit_events(at); CREATE INDEX IF NOT EXISTS ix_exc_f ON exceptions(finding_id); CREATE INDEX IF NOT EXISTS ix_login ON login_attempts(at);"""

def get_setting(c, key, default=None):
    r = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return json.loads(r[0]) if r else default
def set_setting(c, key, value):
    c.execute("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, json.dumps(value)))

def policy_days(c, sev, crit):
    r = c.execute("SELECT days FROM policies WHERE severity=? AND criticality=?", (sev, crit or "Unrated")).fetchone()
    if r: return r[0]
    return max(1, round(DEFAULT_SLA_DAYS.get(sev, 90) * CRIT_FACTOR.get(crit or "Unrated", 1.0)))
def compute_due(c, first_seen, sev, crit):
    d = dt.datetime.fromisoformat(first_seen).date() if first_seen else today()
    return (d + dt.timedelta(days=policy_days(c, sev, crit))).isoformat()

def get_or_create_asset(c, host, hostname="", ts=None):
    key = asset_key(host, hostname); ts = ts or now_iso()
    r = c.execute("SELECT id FROM assets WHERE asset_key=?", (key,)).fetchone()
    if r: 
        if hostname: c.execute("UPDATE assets SET hostname=COALESCE(NULLIF(hostname,''),?) WHERE id=?", (hostname, r[0]))
        return r[0]
    isip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f:]+:[0-9a-f:]*$", key))
    cur = c.execute("INSERT INTO assets(asset_key,hostname,ip,first_seen,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                    (key, hostname or ("" if isip else key), key if isip else "", ts, ts, ts))
    return cur.lastrowid

def migrate(path):
    """Idempotent. Backs up an existing DB before the first structural upgrade. Returns the open connection."""
    existed = os.path.exists(path) and os.path.getsize(path) > 0
    c = connect(path)
    has_settings = c.execute("SELECT 1 FROM sqlite_master WHERE name='settings'").fetchone()
    ver = int(get_setting(c, "schema_version", 0)) if has_settings else 0
    if existed and ver < SCHEMA_VERSION:
        c.execute("PRAGMA wal_checkpoint(FULL)")
        bak = f"{path}.bak-{utcnow().strftime('%Y%m%d-%H%M%S')}"
        if not os.path.exists(bak): shutil.copy2(path, bak)
    c.executescript(DDL)
    have = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
    for col, typ in NEW_FINDING_COLS.items():
        if col not in have: c.execute(f"ALTER TABLE findings ADD COLUMN {col} {typ}")
    with tx(c):
        for sev, base in DEFAULT_SLA_DAYS.items():
            for crit, f in CRIT_FACTOR.items():
                c.execute("INSERT OR IGNORE INTO policies VALUES(?,?,?)", (sev, crit, max(1, round(base * f))))
        if ver < 3: _migrate_legacy_rows(c)
        c.execute("INSERT OR IGNORE INTO settings VALUES('schema_version','0')")
        set_setting(c, "schema_version", SCHEMA_VERSION)
    c.executescript(INDEXES)
    return c

def _migrate_legacy_rows(c):
    """Upgrade rows written by the original single-table app. Preserves ids, status intent and timestamps."""
    rows = c.execute("SELECT * FROM findings WHERE fingerprint IS NULL").fetchall()
    if not rows: return
    ts = now_iso(); sid = None
    sid = c.execute("INSERT INTO scans(source_type,filename,imported_at,status,parsed_count,notes) VALUES('Legacy',?,?,'Partial',?,?)",
        ("pre-upgrade findings", ts, len(rows), "Findings imported before VulnTrack Sentinel. Completeness unknown, so this scan cannot verify remediation.")).lastrowid
    for r in rows:
        f = dict(r); aid = get_or_create_asset(c, f["host"], "", f.get("first_seen") or ts)
        cve = ", ".join(sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", f["name"] or "")))[:10])
        src = f["src"] or "Unknown"
        if src == "OpenVAS": csrc = "OpenVAS reported" if (f["cvss"] or 0) > 0 else "None"
        elif src == "Nmap": csrc = "Nmap script output (vulners)" if cve else ("Heuristic estimate (not CVSS)" if (f["cvss"] or 0) > 0 else "None")
        else: csrc = "Unknown (legacy)"
        port, _ = split_port(f["port"])
        fp = fingerprint(asset_key(f["host"]), f["port"], src, vuln_key(f["name"], cve))
        old = f["status"] or "Open"
        new = {"Fixed": S_FIXED, "Accepted Risk": S_ACCEPTED}.get(old, old if old in STATUSES else S_OPEN)
        crit = "Unrated"; fs = f.get("first_seen") or ts
        try:
            c.execute("""UPDATE findings SET asset_id=?,fingerprint=?,cve=?,cvss_source=?,status=?,last_seen=?,first_scan_id=?,last_scan_id=?,due_date=?,service=?,evidence=COALESCE(evidence,''),exploit_status='Unknown' WHERE id=?""",
                  (aid, fp, cve, csrc, new, f.get("updated") or fs, sid, sid, compute_due(c, fs, f["sev"], crit), "", f["id"]))
        except sqlite3.IntegrityError:   # duplicate legacy fingerprint (same logical finding): keep both rows, disambiguate
            c.execute("UPDATE findings SET asset_id=?,fingerprint=?,cve=?,cvss_source=?,status=?,first_scan_id=?,last_scan_id=? WHERE id=?",
                      (aid, fp + f["id"], cve, csrc, new, sid, sid, f["id"]))
        c.execute("INSERT OR IGNORE INTO sightings VALUES(?,?)", (sid, f["id"]))
        c.execute("INSERT OR IGNORE INTO scan_assets VALUES(?,?)", (sid, aid))
        c.execute("INSERT INTO finding_history(finding_id,at,actor_name,kind,from_value,to_value,note) VALUES(?,?,?,?,?,?,?)",
                  (f["id"], ts, "migration", "migrated", old, new, "Migrated from legacy schema" + ("; legacy 'Fixed' is NOT treated as verified" if old == "Fixed" else "")))
        if new == S_ACCEPTED:
            c.execute("INSERT INTO exceptions(finding_id,requested_at,justification,status,review_note) VALUES(?,?,?,?,?)",
                      (f["id"], ts, "Migrated from legacy 'Accepted Risk' status. No justification was recorded.", "Re-review required",
                       "Legacy acceptance had no approver or expiry; requires review."))
            c.execute("UPDATE findings SET status=? WHERE id=?", (S_REOPENED, f["id"]))
            c.execute("INSERT INTO finding_history(finding_id,at,actor_name,kind,from_value,to_value,note) VALUES(?,?,?,?,?,?,?)",
                      (f["id"], ts, "migration", "status", S_ACCEPTED, S_REOPENED, "Legacy risk acceptance lacked justification/approver/expiry; sent to re-review"))
