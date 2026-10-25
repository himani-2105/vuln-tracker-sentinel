"""Operations CLI:  python manage.py <command>
  create-admin            create an administrator (password prompted, never stored in the repo)
  backup [DEST]           consistent online backup of the SQLite DB
  restore SRC             restore a backup (stop the app first; current DB is kept as .pre-restore)
  audit-verify            verify the audit hash chain
  seed-demo               load the synthetic demo scenario + demo users with RANDOM passwords printed once (demo only)"""
import os, sys, getpass, sqlite3, shutil, secrets, datetime as dt
os.environ.setdefault("VULNTRACK_NO_AUTOAPP", "1")
import db, audit, security, workflow

def path(): return os.environ.get("DB_PATH", "tracker.db")
def cmd_create_admin():
    c = db.migrate(path()); un = input("Admin username: ").strip()
    pw = getpass.getpass("Password (min 12 chars): "); 
    if pw != getpass.getpass("Repeat: "): sys.exit("passwords differ")
    e = security.validate_password(pw)
    if e: sys.exit(e)
    with db.tx(c):
        c.execute("INSERT INTO users(username,display_name,role,password_hash,created_at) VALUES(?,?,?,?,?)", (un, un, "admin", security.hash_pw(pw), db.now_iso())); audit.log(c, workflow.SYSTEM, "user.create_admin_cli", "user", un)
    print("admin created")
def cmd_backup(dest=None):
    dest = dest or f"{path()}.backup-{db.utcnow().strftime('%Y%m%d-%H%M%S')}"
    src = sqlite3.connect(path()); out = sqlite3.connect(dest); src.backup(out); out.close(); src.close(); print("backup written:", dest)
def cmd_restore(src):
    if not os.path.exists(src): sys.exit("backup file not found")
    chk = sqlite3.connect(src); ok = chk.execute("PRAGMA integrity_check").fetchone()[0]; chk.close()
    if ok != "ok": sys.exit("backup failed integrity check")
    if os.path.exists(path()): shutil.copy2(path(), path() + ".pre-restore")
    for ext in ("-wal", "-shm"):
        if os.path.exists(path() + ext): os.remove(path() + ext)
    shutil.copy2(src, path()); print("restored. previous DB kept at", path() + ".pre-restore")
def cmd_audit_verify():
    c = db.migrate(path()); print(audit.verify_chain(c))

def backdate(c, sid, days):
    ts = (db.utcnow() - dt.timedelta(days=days)).isoformat(timespec="seconds")
    c.execute("UPDATE scans SET imported_at=? WHERE id=?", (ts, sid))
    c.execute("UPDATE findings SET first_seen=?,updated=?,last_seen=? WHERE first_scan_id=?", (ts, ts, ts, sid))
    c.execute("UPDATE findings SET last_seen=? WHERE last_scan_id=?", (ts, sid))
    c.execute("UPDATE finding_history SET at=? WHERE kind='detected' AND note LIKE ?", (ts, f"%scan #{sid} %"))
    c.execute("UPDATE finding_history SET at=? WHERE note LIKE ?", (ts, f"%scan #{sid} %"))
    c.execute("UPDATE findings SET verified_at=? WHERE verification_scan_id=?", (ts, sid))
    for f in c.execute("SELECT id,sev,first_seen,asset_id FROM findings WHERE first_scan_id=?", (sid,)).fetchall():
        crit = c.execute("SELECT criticality FROM assets WHERE id=?", (f["asset_id"],)).fetchone()[0]
        c.execute("UPDATE findings SET due_date=? WHERE id=?", (db.compute_due(c, f["first_seen"], f["sev"], crit), f["id"]))

def cmd_seed_demo():
    from parsers import parse_report
    c = db.migrate(path())
    if c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]: sys.exit("refusing to seed: database already contains findings (demo seed never overwrites data)")
    creds = {}
    with db.tx(c):
        for un, role, name in (("admin", "admin", "Demo Admin"), ("analyst", "analyst", "Demo Security Analyst"), ("owner1", "owner", "Demo Remediation Owner"), ("auditor", "auditor", "Demo Auditor")):
            if c.execute("SELECT 1 FROM users WHERE username=?", (un,)).fetchone(): continue
            pw = secrets.token_urlsafe(14); creds[un] = pw
            c.execute("INSERT INTO users(username,display_name,role,password_hash,created_at) VALUES(?,?,?,?,?)", (un, name, role, security.hash_pw(pw), db.now_iso()))
    uid = lambda n: c.execute("SELECT id FROM users WHERE username=?", (n,)).fetchone()[0]
    an = dict(c.execute("SELECT id,username,role FROM users WHERE username='analyst'").fetchone()); ow = dict(c.execute("SELECT id,username,role FROM users WHERE username='owner1'").fetchone())
    ad = dict(c.execute("SELECT id,username,role FROM users WHERE username='admin'").fetchone())
    d = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", "demo")
    def imp(fn, days, partial=False):
        raw = open(os.path.join(d, fn), "rb").read()
        with db.tx(c): r = workflow.ingest_scan(c, parse_report(fn, raw), fn, raw, an, partial=partial, notes="synthetic demo fixture")
        with db.tx(c): backdate(c, r["scan_id"], days)
        return r
    imp("demo1_nmap_baseline.xml", 34); imp("demo2_openvas_baseline.csv", 34); imp("demo3_nmap_partial.xml", 20, partial=True)
    A = lambda k: c.execute("SELECT id FROM assets WHERE asset_key=?", (k,)).fetchone()[0]
    with db.tx(c):      # analyst enriches asset context (this is what moves confidence from Low to Medium/High)
        for k, env, crit, bus, exp, src in (("192.168.56.101", "Production", "High", "Important", "Internet-facing", "lab firewall rule review (demo)"), ("192.168.56.102", "Production", "Critical", "Mission-critical", "Internal", "lab network diagram (demo)"),
                                           ("192.168.56.103", "Staging", "Medium", "Supporting", "Internal", "lab network diagram (demo)"), ("192.168.56.104", "Development", "Low", "Supporting", "Unknown", "")):
            c.execute("UPDATE assets SET environment=?,criticality=?,business_importance=?,internet_exposure=?,exposure_source=?,owner_id=? WHERE id=?", (env, crit, bus, exp, src, uid("owner1"), A(k)))
            audit.log(c, an, "asset.update", "asset", A(k), None, {"environment": env, "criticality": crit}); 
            for f in c.execute("SELECT id,sev,first_seen FROM findings WHERE asset_id=?", (A(k),)).fetchall(): c.execute("UPDATE findings SET due_date=? WHERE id=?", (db.compute_due(c, f["first_seen"], f["sev"], crit), f["id"]))
        c.execute("INSERT INTO relationships(src_asset_id,dst_asset_id,label,kind,evidence,created_by,created_at) VALUES(?,?,?,?,?,?,?)", (A("192.168.56.101"), A("192.168.56.102"), "app server connects to database", "manual", "Lab design doc (demo, analyst-entered)", an["id"], db.now_iso()))
        c.execute("INSERT INTO relationships(src_asset_id,dst_asset_id,label,kind,evidence,created_by,created_at) VALUES(?,?,?,?,?,?,?)", (A("192.168.56.103"), A("192.168.56.102"), "jump host administers database", "manual", "Lab design doc (demo, analyst-entered)", an["id"], db.now_iso()))
    fid = lambda needle, host: c.execute("SELECT id FROM findings WHERE name LIKE ? AND host=? LIMIT 1", (needle, host)).fetchone()[0]
    with db.tx(c):
        for f in c.execute("SELECT id,sev FROM findings WHERE sev IN ('Critical','High') OR name LIKE '%Samba%' OR name LIKE '%telnet%'").fetchall(): c.execute("UPDATE findings SET owner_id=? WHERE id=?", (uid("owner1"), f["id"]))
        workflow.transition(c, fid("%telnet%", "192.168.56.101"), "In Progress", ow, "Disabling telnetd, moving admins to SSH keys")
        workflow.transition(c, fid("%telnet%", "192.168.56.101"), workflow.db.S_FIXED, ow, "telnetd disabled and package removed (change CHG-1042)", "CHG-1042")
        workflow.transition(c, fid("%Samba%", "192.168.56.101"), "In Progress", ow, "Samba upgrade scheduled")
        workflow.transition(c, fid("%Samba%", "192.168.56.101"), workflow.db.S_FIXED, ow, "Samba upgraded in change window CHG-1043", "CHG-1043")
    imp("demo4_nmap_followup.xml", 2)
    from datetime import date, timedelta
    with db.tx(c):
        e1 = fid("%MySQL%", "192.168.56.102")
        c.execute("INSERT INTO exceptions(finding_id,requested_by,requested_at,justification,compensating_controls,status,expires_at) VALUES(?,?,?,?,?,'Pending',?)",
                  (e1, ow["id"], db.now_iso(), "Vendor application only supports this MySQL version until the Q4 migration is completed.", "Database only reachable from the jump host; connection logging enabled.", (date.today() + timedelta(days=60)).isoformat()))
        workflow.history(c, e1, ow, "exception", None, "Pending", "Risk exception requested (demo)")
        e2 = fid("%OpenSSH%", "192.168.56.103")
        c.execute("INSERT INTO exceptions(finding_id,requested_by,requested_at,justification,compensating_controls,status,approver_id,approved_at,expires_at) VALUES(?,?,?,?,?,'Approved',?,?,?)",
                  (e2, ow["id"], db.now_iso(), "Upgrade blocked by jump-host image freeze until the next release train.", "SSH restricted to admin VPN range; key-only auth enforced.", ad["id"], db.now_iso(), (date.today() + timedelta(days=9)).isoformat()))
        c.execute("UPDATE findings SET status='Risk Accepted' WHERE id=?", (e2,)); workflow.history(c, e2, ad, "status", "Open", "Risk Accepted", "Exception approved (demo) - not a fix")
        audit.log(c, ad, "exception.approve", "exception", 2, None, {"status": "Approved"})
    print("\nDemo data loaded. One-time demo credentials (shown once, not stored anywhere):")
    for k, v in creds.items(): print(f"  {k:8s} {v}")
    print("\nOpen http://127.0.0.1:8000 and sign in.")

if __name__ == "__main__":
    a = sys.argv[1:]
    {"create-admin": cmd_create_admin, "backup": lambda: cmd_backup(*a[1:2]), "restore": lambda: cmd_restore(a[1]) if len(a) > 1 else sys.exit("usage: restore SRC"), "audit-verify": cmd_audit_verify, "seed-demo": cmd_seed_demo}.get(a[0] if a else "", lambda: print(__doc__))()
