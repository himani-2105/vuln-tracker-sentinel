"""Scan ingestion, lifecycle matching, status state machine, scan comparison, exception expiry."""
import hashlib, datetime as dt
import db, audit
from db import (S_OPEN, S_TRIAGED, S_PROG, S_FIXED, S_VERIFIED, S_ACCEPTED, S_REOPENED, UNRESOLVED, now_iso, today)
SYSTEM = {"id": None, "username": "system", "role": "system"}

class WorkflowError(ValueError):
    def __init__(self, msg, code=400): super().__init__(msg); self.code = code

TRANSITIONS = {
    S_OPEN: {S_TRIAGED, S_PROG, S_FIXED},
    S_TRIAGED: {S_OPEN, S_PROG, S_FIXED},
    S_PROG: {S_TRIAGED, S_FIXED},
    S_FIXED: {S_VERIFIED, S_REOPENED, S_PROG},
    S_VERIFIED: {S_REOPENED},
    S_ACCEPTED: {S_REOPENED},               # entered ONLY via an approved exception
    S_REOPENED: {S_TRIAGED, S_PROG, S_FIXED},
}
OWNER_MAY = {S_PROG, S_FIXED}               # remediation owners (own findings only)

def history(c, fid, actor, kind, frm=None, to=None, note=None, evidence=None):
    c.execute("INSERT INTO finding_history(finding_id,at,actor_id,actor_name,kind,from_value,to_value,note,evidence_ref) VALUES(?,?,?,?,?,?,?,?,?)",
              (fid, now_iso(), actor.get("id"), actor.get("username"), kind, frm, to, note, evidence))

def transition(c, fid, to, actor, note="", evidence="", ip=None, system_scan=None):
    """Validated status change. Caller supplies the transaction. Returns the new status."""
    f = c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not f: raise WorkflowError("finding not found", 404)
    frm = f["status"]; role = actor.get("role")
    if to == S_ACCEPTED: raise WorkflowError("Risk Accepted can only be set by approving a risk exception", 400)
    if to not in TRANSITIONS.get(frm, set()): raise WorkflowError(f"transition '{frm}' -> '{to}' is not allowed", 409)
    if role == "auditor": raise WorkflowError("read-only role", 403)
    if role == "owner":
        if f["owner_id"] != actor.get("id"): raise WorkflowError("remediation owners can only change findings assigned to them", 403)
        if to not in OWNER_MAY: raise WorkflowError("remediation owners may only mark findings In Progress or Fixed (pending verification)", 403)
    if to == S_FIXED and len((note or "").strip()) < 10: raise WorkflowError("describe the remediation performed (min 10 characters)")
    if to in (S_REOPENED, S_OPEN) and len((note or "").strip()) < 5: raise WorkflowError("a reason is required")
    sets, vals = ["status=?", "updated=?"], [to, now_iso()]
    if to == S_FIXED: sets += ["fixed_at=?", "fixed_by=?"]; vals += [now_iso(), actor.get("id")]
    if to == S_REOPENED: sets.append("reopen_count=COALESCE(reopen_count,0)+1"); sets += ["verified_at=NULL", "verification_method=NULL"]
    if to == S_VERIFIED:
        if system_scan is None:   # manual verification path
            if role not in ("admin", "analyst"): raise WorkflowError("only security analysts or admins can verify remediation", 403)
            if f["fixed_by"] is not None and f["fixed_by"] == actor.get("id"): raise WorkflowError("verification must be performed by someone other than the person who marked it fixed", 403)
            if len((evidence or "").strip()) < 5 or len((note or "").strip()) < 10: raise WorkflowError("manual verification requires a note and an evidence reference")
            method, vscan = "manual-evidence", None
        else: method, vscan = "rescan", system_scan
        sets += ["verified_at=?", "verified_by=?", "verification_method=?", "verification_scan_id=?"]; vals += [now_iso(), actor.get("id"), method, vscan]
    c.execute(f"UPDATE findings SET {','.join(sets)} WHERE id=?", vals + [fid])
    history(c, fid, actor, "status", frm, to, note, evidence)
    audit.log(c, actor, "finding.verify" if to == S_VERIFIED else "finding.status", "finding", fid, {"status": frm}, {"status": to, "note": note, "evidence": evidence}, ip)
    return to

# ---------------- scan ingestion ----------------
def ingest_scan(c, parsed, filename, raw, actor, partial=False, extra_hosts=(), notes="", ip=None):
    """Import parsed findings as one scan run. Resolution is inferred ONLY for assets the scan demonstrably covered,
    from a Complete scan of the same source type. Partial/failed scans never close anything."""
    sha = hashlib.sha256(raw).hexdigest()
    if c.execute("SELECT id FROM scans WHERE sha256=? AND status!='Failed'", (sha,)).fetchone(): raise WorkflowError("this exact file was already imported", 409)
    src = parsed["source"]; ts = now_iso(); items = parsed["items"]
    status = "Partial" if (partial or parsed["rejected"] > 0) else "Complete"
    sid = c.execute("INSERT INTO scans(source_type,filename,sha256,imported_at,imported_by,status,parsed_count,rejected_count,notes) VALUES(?,?,?,?,?,?,?,?,?)",
                    (src, (filename or "")[:200], sha, ts, actor.get("id"), status, len(items), parsed["rejected"], notes[:500])).lastrowid
    covered = set()
    for h in list(parsed.get("hosts", [])) + [x.strip() for x in extra_hosts if x.strip()]:
        covered.add(db.get_or_create_asset(c, h, "", ts))
    new = reopened = 0; seen = set()
    for it in items:
        aid = db.get_or_create_asset(c, it["host"], it.get("hostname", ""), ts); covered.add(aid)
        c.execute("UPDATE assets SET last_scan_id=?, updated_at=? WHERE id=?", (sid, ts, aid))
        fp = db.fingerprint(db.asset_key(it["host"], it.get("hostname", "")), it["port"], src, db.vuln_key(it["name"], it.get("cve", "")))
        f = c.execute("SELECT * FROM findings WHERE fingerprint=?", (fp,)).fetchone()
        if f is None:
            crit = c.execute("SELECT criticality FROM assets WHERE id=?", (aid,)).fetchone()[0]
            fid = it["id"]
            if c.execute("SELECT 1 FROM findings WHERE id=?", (fid,)).fetchone(): fid = fp[:16]
            c.execute("""INSERT INTO findings(id,host,port,name,cvss,sev,rem,src,owasp,status,first_seen,updated,asset_id,fingerprint,cve,cvss_source,cvss_vector,service,evidence,last_seen,first_scan_id,last_scan_id,due_date,exploit_status)
                         VALUES(?,?,?,?,?,?,?,?,?,'Open',?,?,?,?,?,?,?,?,?,?,?,?,?,'Unknown')""",
                      (fid, it["host"], it["port"], it["name"], it["cvss"], it["sev"], it["rem"], it["src"], it["owasp"], ts, ts, aid, fp, it.get("cve", ""),
                       it.get("cvss_source", ""), it.get("cvss_vector", ""), it.get("service", ""), it.get("evidence", ""), ts, sid, sid, db.compute_due(c, ts, it["sev"], crit)))
            history(c, fid, SYSTEM, "detected", None, S_OPEN, f"First detected in scan #{sid} ({src})"); new += 1; seen.add(fid)
        else:
            fid = f["id"]; seen.add(fid)
            c.execute("UPDATE findings SET last_seen=?,last_scan_id=?,cvss=?,sev=?,cvss_source=?,evidence=?,cve=?,updated=? WHERE id=?",
                      (ts, sid, it["cvss"], it["sev"], it.get("cvss_source", ""), it.get("evidence", ""), it.get("cve", "") or f["cve"], f["updated"], fid))
            if f["status"] in (S_VERIFIED, S_FIXED):
                why = "Detected again after it was marked verified" if f["status"] == S_VERIFIED else "Detected again after being marked fixed: fix not confirmed"
                c.execute("UPDATE findings SET status=?,reopen_count=COALESCE(reopen_count,0)+1,updated=?,verified_at=NULL,verification_method=NULL WHERE id=?", (S_REOPENED, ts, fid))
                history(c, fid, SYSTEM, "status", f["status"], S_REOPENED, f"{why} (scan #{sid})"); reopened += 1
                audit.log(c, SYSTEM, "finding.reopen", "finding", fid, {"status": f["status"]}, {"status": S_REOPENED, "scan": sid}, ip)
        c.execute("INSERT OR IGNORE INTO sightings VALUES(?,?)", (sid, fid))
    for aid in covered: c.execute("INSERT OR IGNORE INTO scan_assets VALUES(?,?)", (sid, aid))
    resolved = 0
    if status == "Complete" and covered:
        q = ",".join("?" * len(covered))
        cand = c.execute(f"SELECT id,status FROM findings WHERE src=? AND asset_id IN ({q}) AND status IN (?,?,?,?,?) AND manual=0", [src, *covered, S_OPEN, S_TRIAGED, S_PROG, S_FIXED, S_REOPENED]).fetchall()
        for r in cand:
            if r["id"] in seen: continue
            # absent from a complete scan of a covered asset by the same scanner family => verified by re-scan
            c.execute("UPDATE findings SET status=?,verified_at=?,verification_method='rescan',verification_scan_id=?,verified_by=NULL,updated=? WHERE id=?", (S_VERIFIED, ts, sid, ts, r["id"]))
            history(c, r["id"], SYSTEM, "verification", r["status"], S_VERIFIED, f"Absent from complete {src} scan #{sid} covering this asset", f"scan:{sid}")
            audit.log(c, SYSTEM, "finding.verify", "finding", r["id"], {"status": r["status"]}, {"status": S_VERIFIED, "scan": sid, "method": "rescan"}, ip); resolved += 1
    c.execute("UPDATE scans SET new_count=?,resolved_count=? WHERE id=?", (new, resolved, sid))
    audit.log(c, actor, "scan.upload", "scan", sid, None, {"file": filename, "source": src, "status": status, "parsed": len(items), "rejected": parsed["rejected"], "new": new, "resolved": resolved, "reopened": reopened, "sha256": sha}, ip)
    return {"scan_id": sid, "status": status, "parsed": len(items), "rejected": parsed["rejected"], "new": new, "resolved": resolved, "reopened": reopened, "assets": len(covered)}

def record_failed_scan(c, filename, raw, actor, error, ip=None):
    sid = c.execute("INSERT INTO scans(source_type,filename,sha256,imported_at,imported_by,status,error) VALUES('Unknown',?,?,?,?,'Failed',?)",
                    ((filename or "")[:200], hashlib.sha256(raw).hexdigest(), now_iso(), actor.get("id"), error[:300])).lastrowid
    audit.log(c, actor, "scan.upload_rejected", "scan", sid, None, {"file": filename, "error": error}, ip); return sid

def compare_scans(c, a_id, b_id):
    """Compare scan A (older) to scan B (newer). Same-source scans only; unassessed assets are reported separately, never as resolved."""
    A = c.execute("SELECT * FROM scans WHERE id=?", (a_id,)).fetchone(); B = c.execute("SELECT * FROM scans WHERE id=?", (b_id,)).fetchone()
    if not A or not B: raise WorkflowError("scan not found", 404)
    sa = {r[0] for r in c.execute("SELECT finding_id FROM sightings WHERE scan_id=?", (a_id,))}
    sb = {r[0] for r in c.execute("SELECT finding_id FROM sightings WHERE scan_id=?", (b_id,))}
    covered_b = {r[0] for r in c.execute("SELECT asset_id FROM scan_assets WHERE scan_id=?", (b_id,))}
    before = {r[0] for r in c.execute("SELECT DISTINCT finding_id FROM sightings WHERE scan_id<?", (a_id,))}
    info = {r["id"]: r for r in c.execute("SELECT id,asset_id,name,sev,host,port,status,reopen_count FROM findings WHERE id IN (%s)" % ",".join("?" * len(sa | sb)), list(sa | sb))} if (sa | sb) else {}
    def pack(ids): return [{k: info[i][k] for k in ("id", "name", "sev", "host", "port", "status")} for i in sorted(ids, key=lambda x: info[x]["host"] + info[x]["port"]) if i in info]
    reopened = {i for i in sb if i in info and info[i]["status"] == S_REOPENED and i in sa | before}
    recurring = {i for i in sb - sa if i in before}
    gone = sa - sb
    resolved = {i for i in gone if i in info and info[i]["asset_id"] in covered_b and B["status"] == "Complete" and B["source_type"] == A["source_type"]}
    return {"a": dict(A), "b": dict(B), "new": pack(sb - sa - recurring), "persistent": pack(sa & sb), "resolved": pack(resolved), "recurring": pack(recurring), "reopened": pack(reopened),
            "not_assessed": pack(gone - resolved),
            "caveat": None if B["status"] == "Complete" and A["source_type"] == B["source_type"] else
              "Scan B is partial/failed or from a different source, so missing findings are listed as 'not assessed', not resolved."}

def expire_exceptions(c, ref_date=None):
    """Approved exceptions past expiry require re-review; the finding is reopened, never auto-verified."""
    d = (ref_date or today()).isoformat(); n = 0
    for e in c.execute("SELECT * FROM exceptions WHERE status='Approved' AND expires_at<?", (d,)).fetchall():
        c.execute("UPDATE exceptions SET status='Re-review required', review_note=? WHERE id=?", (f"Expired on {e['expires_at']}", e["id"]))
        f = c.execute("SELECT status FROM findings WHERE id=?", (e["finding_id"],)).fetchone()
        if f and f["status"] == S_ACCEPTED:
            c.execute("UPDATE findings SET status=?,reopen_count=COALESCE(reopen_count,0)+1,updated=? WHERE id=?", (S_REOPENED, now_iso(), e["finding_id"]))
            history(c, e["finding_id"], SYSTEM, "status", S_ACCEPTED, S_REOPENED, f"Risk exception #{e['id']} expired; re-review required")
        audit.log(c, SYSTEM, "exception.expire", "exception", e["id"], {"status": "Approved"}, {"status": "Re-review required"}); n += 1
    return n
