"""Shared read-side queries used by the API and by reports."""
import datetime as dt, json
import db, risk
from db import UNRESOLVED
SORT_KEYS = {"id", "name", "cvss", "sev", "host", "first_seen", "last_seen", "status", "due_date", "risk", "owner", "environment"}
SEV_ORDER = {s: i for i, s in enumerate(db.SEVERITIES)}

def weights(c):
    w = dict(risk.DEFAULT_WEIGHTS); w.update(db.get_setting(c, "risk_weights", {}) or {}); return w
def kev_set(c): return frozenset(r[0] for r in c.execute("SELECT cve FROM intel_kev"))

def shape(r, wts, kev, today):
    f = dict(r)
    a = {"criticality": f.pop("a_crit"), "internet_exposure": f.pop("a_expo"), "business_importance": f.pop("a_bus"), "exposure_source": f.pop("a_expsrc")}
    res = risk.assess(f, a, wts, kev, today)
    left, overdue = risk.sla_state(f, today)
    f.update(environment=f.pop("a_env"), hostname=f.pop("a_hostname") or "", owner_name=f.pop("owner_name"), days_left=left, overdue=overdue, risk=res,
             asset_criticality=a["criticality"], internet_exposure=a["internet_exposure"])
    return f

BASE = """SELECT f.*, a.environment a_env, a.hostname a_hostname, a.criticality a_crit, a.internet_exposure a_expo, a.business_importance a_bus, a.exposure_source a_expsrc,
 COALESCE(u.display_name,u.username) owner_name FROM findings f LEFT JOIN assets a ON a.id=f.asset_id LEFT JOIN users u ON u.id=f.owner_id"""

def query_findings(c, flt=None, sort="risk", direction="desc", today=None, include_evidence=False):
    flt = flt or {}; today = today or db.today(); w, p = [], []
    if flt.get("severity"): w.append("f.sev=?"); p.append(flt["severity"])
    if flt.get("status") == "open": w.append("f.status IN (%s)" % ",".join("?" * len(UNRESOLVED))); p += UNRESOLVED
    elif flt.get("status"): w.append("f.status=?"); p.append(flt["status"])
    if flt.get("asset"): w.append("f.asset_id=?"); p.append(int(flt["asset"]))
    if flt.get("environment"): w.append("a.environment=?"); p.append(flt["environment"])
    if flt.get("cve"): w.append("f.cve LIKE ?"); p.append("%" + flt["cve"].upper().replace("%", "") + "%")
    if flt.get("owner"): w.append("f.owner_id=?"); p.append(int(flt["owner"]))
    if flt.get("unassigned"): w.append("f.owner_id IS NULL")
    if flt.get("scan"): w.append("f.id IN (SELECT finding_id FROM sightings WHERE scan_id=?)"); p.append(int(flt["scan"]))
    if flt.get("q"):
        like = "%" + flt["q"].replace("%", "").replace("_", "") + "%"
        w.append("(f.id LIKE ? OR f.name LIKE ? OR f.cve LIKE ? OR f.host LIKE ? OR a.hostname LIKE ?)"); p += [like] * 5
    sql = BASE + (" WHERE " + " AND ".join(w) if w else "")
    wts, kev = weights(c), kev_set(c)
    rows = [shape(r, wts, kev, today) for r in c.execute(sql, p)]
    if flt.get("overdue"): rows = [r for r in rows if r["overdue"]]
    if flt.get("age_min") is not None or flt.get("age_max") is not None:
        age = lambda r: (today - dt.datetime.fromisoformat(r["first_seen"]).date()).days
        rows = [r for r in rows if r["status"] in UNRESOLVED and (flt.get("age_min") is None or age(r) >= flt["age_min"]) and (flt.get("age_max") is None or age(r) <= flt["age_max"])]
    if flt.get("category"): rows = [r for r in rows if r["risk"]["category"] == flt["category"]]
    if not include_evidence:
        for r in rows: r.pop("evidence", None)
    key = {"risk": lambda r: (r["risk"]["score"] if r["risk"]["score"] is not None else -1), "sev": lambda r: SEV_ORDER.get(r["sev"], 9),
           "owner": lambda r: (r["owner_name"] or "~").lower(), "cvss": lambda r: r["cvss"] or 0, "due_date": lambda r: r["due_date"] or "9999",
           "environment": lambda r: r["environment"] or ""}.get(sort, lambda r: (str(r.get(sort) or "")).lower())
    rows.sort(key=key, reverse=(direction == "desc"))
    return rows

def asset_summary(c, today=None):
    today = today or db.today(); fs = query_findings(c, {"status": "open"}, today=today)
    by = {}
    for f in fs: by.setdefault(f["asset_id"], []).append(f)
    out = []
    for a in c.execute("SELECT a.*, COALESCE(u.display_name,u.username) owner_name, (SELECT imported_at FROM scans s WHERE s.id=a.last_scan_id) last_scan FROM assets a LEFT JOIN users u ON u.id=a.owner_id ORDER BY a.asset_key"):
        a = dict(a); items = by.get(a["id"], [])
        scores = sorted((i["risk"]["score"] for i in items if i["risk"]["score"] is not None), reverse=True)
        top = scores[0] if scores else None
        overall = round(min(100, (top or 0) + 0.5 * sum(scores[1:4])) , 1) if scores else 0.0   # max + damped next three; documented
        sevs = [i["sev"] for i in items]
        a.update(open_findings=len(items), highest_severity=min(sevs, key=lambda s: SEV_ORDER.get(s, 9)) if sevs else None, overall_risk=overall,
                 incomplete=sum(1 for i in items if i["risk"]["category"] == "Incomplete"), overdue=sum(1 for i in items if i["overdue"]))
        out.append(a)
    return out
