import datetime as dt, json, sqlite3, pytest, risk, db, workflow, audit, reports
from conftest import nmap_xml, FTP, HTTP, TEL
from db import S_FIXED, S_VERIFIED, S_REOPENED, S_ACCEPTED
T = dt.date(2026, 10, 10)
F = dict(cvss=9.8, cvss_source="OpenVAS reported", status="Open", first_seen="2026-10-01T00:00:00+00:00", due_date="2026-10-20", cve="")
# ---------- risk ----------
def test_cvss_missing_is_incomplete_not_invented():
    r = risk.assess(dict(F, cvss=7.5, cvss_source="Heuristic estimate (not CVSS)"), {"criticality": "Critical", "internet_exposure": "Internet-facing"}, today=T)
    assert r["category"] == "Incomplete" and r["provisional"] and any("CVSS" in m for m in r["missing"]) and "cvss" not in r["components"]
def test_missing_context_lowers_confidence_and_lists_gaps():
    r = risk.assess(F, {}, today=T); assert r["confidence"] == "Low" and not r["complete"] and len(r["missing"]) >= 4
def test_full_evidence_scores_high_and_explains():
    a = {"criticality": "Critical", "internet_exposure": "Internet-facing", "business_importance": "Mission-critical", "exposure_source": "ext scan"}
    r = risk.assess(dict(F, exploit_status="Exploit confirmed (evidence)"), a, today=T)
    assert r["category"] == "Critical" and r["confidence"] == "High" and r["complete"] and r["score"] > 90 and any("Internet-facing" in x for x in r["factors"])
def test_kev_match_counts_as_evidence_but_absence_does_not():
    assert risk.assess(dict(F, cve="CVE-2024-1"), {}, kev=frozenset({"CVE-2024-1"}), today=T)["components"]["exploit"] == 1.0
    assert "exploit" not in risk.assess(dict(F, cve="CVE-2024-1"), {}, kev=frozenset(), today=T)["components"]
def test_floor_rule_and_overdue_factor():
    r = risk.assess(dict(F, cvss=7.1, exploit_status="Exploit confirmed (evidence)"), {"criticality": "Low", "internet_exposure": "Internal", "business_importance": "Supporting"}, today=T)
    assert r["category"] in ("High", "Critical")
    o = risk.assess(dict(F, due_date="2026-10-01"), {}, today=T); assert any("SLA breached" in x for x in o["factors"]) and "Escalate" in o["next_action"]
def test_closed_findings_not_overdue():
    assert risk.sla_state(dict(F, due_date="2026-01-01", status="Verified Resolved"), T) == (None, False)
# ---------- matching / lifecycle ----------
def ingest(e, raw, partial=False, extra=()):
    from parsers import parse_report
    c = e.db()
    with db.tx(c): r = workflow.ingest_scan(c, parse_report("s.xml", raw), "s.xml", raw, {"id": 1, "username": "t", "role": "analyst"}, partial, extra)
    return c, r
def test_stable_matching_and_new_vs_persistent(env):
    c, r1 = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP)); assert r1["new"] == 2
    c, r2 = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP, TEL)); assert r2["new"] == 1 and c.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
    cmp = workflow.compare_scans(c, r1["scan_id"], r2["scan_id"]); assert len(cmp["persistent"]) == 2 and len(cmp["new"]) == 1 and not cmp["resolved"]
def test_complete_scan_verifies_absent_findings_only_for_covered_assets(env):
    c, r1 = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP)); ingest(env, nmap_xml("10.0.0.2", FTP))
    c, r3 = ingest(env, nmap_xml("10.0.0.1", FTP)); assert r3["resolved"] == 1
    st = {(r["host"], r["port"]): r["status"] for r in c.execute("SELECT host,port,status FROM findings")}
    assert st[("10.0.0.1", "80/tcp")] == S_VERIFIED and st[("10.0.0.1", "21/tcp")] == "Open" and st[("10.0.0.2", "21/tcp")] == "Open"
def test_partial_scan_never_closes_findings(env):
    c, _ = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP)); c, r = ingest(env, nmap_xml("10.0.0.1", FTP), partial=True)
    assert r["status"] == "Partial" and r["resolved"] == 0 and c.execute("SELECT COUNT(*) FROM findings WHERE status=?", (S_VERIFIED,)).fetchone()[0] == 0
def test_scan_with_rejects_is_partial(env):
    from parsers import parse_report; c = env.db(); raw = b"IP,NVT Name,CVSS\n10.0.0.1,A,5\n10.0.0.1,,5\n"
    with db.tx(c): r = workflow.ingest_scan(c, parse_report("r.csv", raw), "r.csv", raw, {"id": 1, "username": "t", "role": "analyst"})
    assert r["status"] == "Partial"
def test_other_scanner_does_not_verify(env):
    from parsers import parse_report; c, _ = ingest(env, nmap_xml("10.0.0.1", FTP)); raw = b"IP,NVT Name,CVSS\n10.0.0.1,Other,5\n"
    with db.tx(c): workflow.ingest_scan(c, parse_report("r.csv", raw), "r.csv", raw, {"id": 1, "username": "t", "role": "analyst"})
    assert c.execute("SELECT status FROM findings WHERE port='21/tcp'").fetchone()[0] == "Open"
def test_recurring_and_reopened(env):
    c, r1 = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP)); c, r2 = ingest(env, nmap_xml("10.0.0.1", FTP))      # HTTP verified
    c, r3 = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP) + b"<!-- rescan 3 -->"); cmp = workflow.compare_scans(c, r2["scan_id"], r3["scan_id"])
    assert len(cmp["recurring"]) == 1 and len(cmp["reopened"]) == 1
    assert c.execute("SELECT status,reopen_count FROM findings WHERE port='80/tcp'").fetchone()[:] == (S_REOPENED, 1)
def test_duplicate_file_rejected(env):
    from parsers import parse_report; ingest(env, nmap_xml("10.0.0.1", FTP)); 
    with pytest.raises(workflow.WorkflowError, match="already imported"): ingest(env, nmap_xml("10.0.0.1", FTP))
def test_comparison_caveat_for_partial_scan(env):
    c, r1 = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP)); c, r2 = ingest(env, nmap_xml("10.0.0.1", FTP), partial=True)
    cmp = workflow.compare_scans(c, r1["scan_id"], r2["scan_id"]); assert not cmp["resolved"] and len(cmp["not_assessed"]) == 1 and cmp["caveat"]
# ---------- status transitions / verification ----------
def mk(env):
    c, _ = ingest(env, nmap_xml("10.0.0.1", FTP)); return c, c.execute("SELECT id FROM findings").fetchone()[0]
AN = {"id": 2, "username": "an", "role": "analyst"}; AN2 = {"id": 3, "username": "an2", "role": "analyst"}
def test_valid_and_invalid_transitions(env):
    c, fid = mk(env)
    with pytest.raises(workflow.WorkflowError, match="not allowed"):
        with db.tx(c): workflow.transition(c, fid, S_VERIFIED, AN, "x" * 12, "evidence-1")
    with db.tx(c): workflow.transition(c, fid, "Triaged", AN)
    with pytest.raises(workflow.WorkflowError, match="exception"):
        with db.tx(c): workflow.transition(c, fid, S_ACCEPTED, AN, "ok ok ok")
def test_manual_fix_is_not_verified(env):
    c, fid = mk(env)
    with db.tx(c): workflow.transition(c, fid, S_FIXED, AN, "patched vsftpd to 3.0.5")
    r = c.execute("SELECT status,verified_at FROM findings WHERE id=?", (fid,)).fetchone(); assert r["status"] == S_FIXED and r["verified_at"] is None
def test_fix_needs_description(env):
    c, fid = mk(env)
    with pytest.raises(workflow.WorkflowError, match="describe"):
        with db.tx(c): workflow.transition(c, fid, S_FIXED, AN, "ok")
def test_manual_verification_rules(env):
    c, fid = mk(env);
    with db.tx(c): workflow.transition(c, fid, S_FIXED, AN, "patched vsftpd to 3.0.5")
    with pytest.raises(workflow.WorkflowError, match="someone other"):
        with db.tx(c): workflow.transition(c, fid, S_VERIFIED, AN, "verified by retest", "RETEST-1")
    with pytest.raises(workflow.WorkflowError, match="evidence"):
        with db.tx(c): workflow.transition(c, fid, S_VERIFIED, AN2, "verified by retest", "")
    with db.tx(c): workflow.transition(c, fid, S_VERIFIED, AN2, "verified by retest nmap", "RETEST-1")
    assert c.execute("SELECT verification_method FROM findings WHERE id=?", (fid,)).fetchone()[0] == "manual-evidence"
def test_owner_limits(env):
    c, fid = mk(env); o = {"id": 4, "username": "owner", "role": "owner"}
    with pytest.raises(workflow.WorkflowError, match="assigned to them"):
        with db.tx(c): workflow.transition(c, fid, "In Progress", o)
    c.execute("UPDATE findings SET owner_id=4 WHERE id=?", (fid,))
    with db.tx(c): workflow.transition(c, fid, "In Progress", o)
    with pytest.raises(workflow.WorkflowError, match="may only"):
        with db.tx(c): workflow.transition(c, fid, "Triaged", o)
def test_auditor_cannot_transition(env):
    c, fid = mk(env)
    with pytest.raises(workflow.WorkflowError, match="read-only"):
        with db.tx(c): workflow.transition(c, fid, "Triaged", {"id": 5, "username": "a", "role": "auditor"})
def test_rescan_confirms_fix_or_reopens(env):
    c, _ = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP)); fid = c.execute("SELECT id FROM findings WHERE port='21/tcp'").fetchone()[0]; fid2 = c.execute("SELECT id FROM findings WHERE port='80/tcp'").fetchone()[0]
    with db.tx(c): workflow.transition(c, fid, S_FIXED, AN, "patched ftp to a fixed version"); workflow.transition(c, fid2, S_FIXED, AN, "patched apache to 2.4")
    ingest(env, nmap_xml("10.0.0.1", FTP))     # ftp still there, http gone
    st = dict(c.execute("SELECT id,status FROM findings").fetchall()); assert st[fid] == S_REOPENED and st[fid2] == S_VERIFIED
# ---------- exceptions expiry ----------
def test_expired_exception_requires_rereview_never_verified(env):
    c, fid = mk(env)
    c.execute("UPDATE findings SET status=? WHERE id=?", (S_ACCEPTED, fid))
    c.execute("INSERT INTO exceptions(finding_id,justification,status,expires_at) VALUES(?,?,?,?)", (fid, "j" * 25, "Approved", "2026-01-01"))
    with db.tx(c): n = workflow.expire_exceptions(c, dt.date(2026, 10, 10))
    assert n == 1 and c.execute("SELECT status FROM exceptions").fetchone()[0] == "Re-review required"
    assert c.execute("SELECT status FROM findings WHERE id=?", (fid,)).fetchone()[0] == S_REOPENED
# ---------- reports ----------
def test_csv_formula_injection_neutralised():
    for bad in ("=cmd|' /C calc'!A0", "+SUM(1)", "-2+3", "@SUM(A1)", "\t=1", " =1"): assert reports.safe_cell(bad).startswith("'")
    assert reports.safe_cell("normal") == "normal" and reports.safe_cell(5) == 5
def test_report_csv_has_metadata_and_safe_cells(env):
    c, _ = ingest(env, nmap_xml("10.0.0.1", FTP)); c.execute("UPDATE findings SET name='=HYPERLINK(\"http://x\")'")
    rep = reports.build(c, "inventory", {}, {"username": "tester"}); out = reports.to_csv(rep).decode()
    assert "# Generated:" in out and "# Filters:" in out and "'=HYPERLINK" in out and "\n=HYPERLINK" not in out and ",=HYPERLINK" not in out
def test_all_reports_build_and_pdf(env):
    c, r1 = ingest(env, nmap_xml("10.0.0.1", FTP)); c, r2 = ingest(env, nmap_xml("10.0.0.1", FTP, HTTP))
    for n in ("inventory", "critical-high", "asset-risk", "sla-breaches", "remediation-performance", "exceptions"): assert reports.to_pdf(reports.build(c, n, {}, {"username": "t"})).startswith(b"%PDF")
    assert reports.build(c, "scan-comparison", {"a": r1["scan_id"], "b": r2["scan_id"]}, {"username": "t"})["rows"]
# ---------- audit ----------
def test_audit_append_only_and_chain(env):
    c = env.db()
    with db.tx(c): audit.log(c, {"id": 1, "username": "x", "role": "admin"}, "a.b", "o", 1, {"password": "hunter2", "n": 1}, {"token": "abc", "ok": 1})
    with db.tx(c): audit.log(c, None, "a.c")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"): c.execute("UPDATE audit_events SET action='x'")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"): c.execute("DELETE FROM audit_events")
    assert audit.verify_chain(c)["ok"]; row = c.execute("SELECT before_json,after_json FROM audit_events WHERE id=1").fetchone()
    assert "hunter2" not in row[0] and "abc" not in row[1] and "[redacted]" in row[0]
    c.execute("DROP TRIGGER audit_no_update"); c.execute("UPDATE audit_events SET action='tampered' WHERE id=1"); assert not audit.verify_chain(c)["ok"]
# ---------- migrations ----------
def test_legacy_db_migration_preserves_data_and_is_idempotent(tmp_path):
    p = str(tmp_path / "l.db"); c = sqlite3.connect(p)
    c.execute("CREATE TABLE findings(id TEXT PRIMARY KEY,host TEXT,port TEXT,name TEXT,cvss REAL,sev TEXT,rem TEXT,src TEXT,owasp TEXT,status TEXT DEFAULT 'Open',first_seen TEXT,updated TEXT)")
    rows = [("a", "10.0.0.5", "21/tcp", "Open ftp (CVE-2011-2523)", 10.0, "Critical", "r", "Nmap", "A06", "Fixed", "2026-08-01T00:00:00+00:00", "2026-09-01T00:00:00+00:00"),
            ("b", "10.0.0.5", "23/tcp", "Open telnet", 7.5, "High", "r", "Nmap", "A02", "Accepted Risk", "2026-08-01T00:00:00+00:00", "2026-08-01T00:00:00+00:00"),
            ("c", "10.0.0.6", "80/tcp", "Apache", 7.5, "High", "r", "OpenVAS", "A06", "Open", "2026-09-01T00:00:00+00:00", "2026-09-01T00:00:00+00:00")]
    c.executemany("INSERT INTO findings VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", rows); c.commit(); c.close()
    c = db.migrate(p); c.close(); c = db.migrate(p)
    st = {r["id"]: r for r in c.execute("SELECT * FROM findings")}
    assert len(st) == 3 and st["a"]["status"] == S_FIXED and st["a"]["verified_at"] is None          # legacy Fixed is not Verified
    assert st["b"]["status"] == S_REOPENED and c.execute("SELECT status FROM exceptions").fetchone()[0] == "Re-review required"   # unjustified acceptance -> re-review
    assert st["b"]["cvss_source"].startswith("Heuristic") and st["c"]["cvss_source"] == "OpenVAS reported" and st["c"]["asset_id"]
    assert c.execute("SELECT COUNT(*) FROM assets").fetchone()[0] == 2 and c.execute("PRAGMA foreign_key_check").fetchall() == []
    import glob; assert glob.glob(p + ".bak-*")                                                      # backup taken before upgrade
def test_fresh_db_and_foreign_keys(tmp_path):
    c = db.migrate(str(tmp_path / "f.db")); assert c.execute("PRAGMA foreign_keys").fetchone()[0] == 1 and c.execute("SELECT COUNT(*) FROM policies").fetchone()[0] == 25
    with pytest.raises(sqlite3.IntegrityError): c.execute("INSERT INTO sightings VALUES(99,'nope')")
