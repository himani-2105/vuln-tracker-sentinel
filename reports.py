"""CSV / PDF report generation. CSV cells are neutralised against spreadsheet formula injection."""
import io, csv, datetime as dt
import db, data
FORMULA = ("=", "+", "-", "@", "\t", "\r", "\n")
def safe_cell(v):
    if isinstance(v, str) and v.lstrip(" ")[:1] in FORMULA: return "'" + v
    return "" if v is None else v

def build(c, name, params, user):
    now = db.utcnow().isoformat(timespec="seconds"); today = db.today()
    flt = {k: params[k] for k in ("severity", "status", "environment", "asset", "cve") if params.get(k)}
    meta = {"generated_at": now, "generated_by": user["username"], "filters": ", ".join(f"{k}={v}" for k, v in flt.items()) or "none"}
    if name == "inventory":
        rows = data.query_findings(c, flt, today=today)
        cols = ["Finding ID", "CVE", "Title", "CVSS", "CVSS source", "Severity", "Priority category", "Priority score (internal, not CVSS)", "Confidence", "Asset", "Port", "Environment", "Status", "Owner", "First seen", "Last seen", "SLA deadline", "Overdue"]
        body = [[r["id"], r["cve"], r["name"], r["cvss"], r["cvss_source"], r["sev"], r["risk"]["category"], r["risk"]["score"], r["risk"]["confidence"], r["host"], r["port"], r["environment"], r["status"], r["owner_name"], r["first_seen"], r["last_seen"], r["due_date"], "yes" if r["overdue"] else "no"] for r in rows]
        title = "Vulnerability inventory"
        summary = {"findings": len(rows), "open": sum(r["status"] in db.UNRESOLVED for r in rows)}
    elif name == "critical-high":
        rows = [r for r in data.query_findings(c, flt, today=today) if r["status"] in db.UNRESOLVED and (r["sev"] in ("Critical", "High") or r["risk"]["category"] in ("Critical", "High"))]
        cols = ["Finding ID", "CVE", "Title", "CVSS", "Severity", "Priority category", "Score", "Why", "Next action", "Asset", "Status", "SLA deadline"]
        body = [[r["id"], r["cve"], r["name"], r["cvss"], r["sev"], r["risk"]["category"], r["risk"]["score"], "; ".join(r["risk"]["factors"]), r["risk"]["next_action"], r["host"], r["status"], r["due_date"]] for r in rows]
        title = "Critical and high-risk findings"; summary = {"findings": len(rows)}
    elif name == "asset-risk":
        rows = sorted(data.asset_summary(c, today), key=lambda a: -a["overall_risk"])
        cols = ["Asset", "Hostname", "Environment", "Owner", "Criticality", "Internet exposure", "Last scan", "Open findings", "Highest severity", "Overall risk (internal)", "Findings with incomplete assessment"]
        body = [[a["asset_key"], a["hostname"], a["environment"], a["owner_name"], a["criticality"], a["internet_exposure"], a["last_scan"], a["open_findings"], a["highest_severity"], a["overall_risk"], a["incomplete"]] for a in rows]
        title = "Asset risk"; summary = {"assets": len(rows), "with open findings": sum(1 for a in rows if a["open_findings"])}
    elif name == "sla-breaches":
        rows = [r for r in data.query_findings(c, dict(flt, status="open"), today=today) if r["overdue"]]
        rows.sort(key=lambda r: r["days_left"])
        cols = ["Finding ID", "Title", "Severity", "Asset", "Owner", "SLA deadline", "Days overdue", "Status"]
        body = [[r["id"], r["name"], r["sev"], r["host"], r["owner_name"], r["due_date"], -r["days_left"], r["status"]] for r in rows]
        title = "SLA breaches"; summary = {"overdue findings": len(rows), "unassigned": sum(1 for r in rows if not r["owner_id"])}
    elif name == "remediation-performance":
        rows = [r for r in data.query_findings(c, flt, today=today)]
        done = [r for r in rows if r["status"] == db.S_VERIFIED and r.get("verified_at")]
        def days(r): return (dt.datetime.fromisoformat(r["verified_at"]) - dt.datetime.fromisoformat(r["first_seen"])).days
        body = []
        for s in db.SEVERITIES:
            tot = [r for r in rows if r["sev"] == s]; ver = [r for r in done if r["sev"] == s]
            met = [r for r in ver if r["due_date"] and r["verified_at"][:10] <= r["due_date"]]
            body.append([s, len(tot), len(ver), sum(r["status"] == db.S_FIXED for r in tot), round(sum(days(r) for r in ver) / len(ver), 1) if ver else "", f"{round(100*len(met)/len(ver))}%" if ver else ""])
        cols = ["Severity", "Total findings", "Verified resolved", "Fixed, pending verification", "Mean days to verified fix", "Verified within SLA"]
        title = "Remediation performance"; viol = len([r for r in rows if r["status"] == db.S_FIXED])
        summary = {"verified resolved": len(done), "fixed but unverified (not counted as resolved)": viol}
    elif name == "scan-comparison":
        import workflow
        cmp = workflow.compare_scans(c, int(params.get("a", 0)), int(params.get("b", 0)))
        cols = ["Change", "Finding ID", "Title", "Severity", "Asset", "Port", "Current status"]; body = []
        for k, lab in (("new", "New"), ("persistent", "Persistent"), ("resolved", "Resolved (verified absent)"), ("recurring", "Recurring"), ("reopened", "Reopened"), ("not_assessed", "Not assessed (asset not covered)")):
            body += [[lab, r["id"], r["name"], r["sev"], r["host"], r["port"], r["status"]] for r in cmp[k]]
        title = f"Scan comparison #{cmp['a']['id']} vs #{cmp['b']['id']}"; summary = {k: len(cmp[k]) for k in ("new", "persistent", "resolved", "recurring", "reopened", "not_assessed")}
        if cmp["caveat"]: summary["caveat"] = cmp["caveat"]
    elif name == "exceptions":
        q = c.execute("""SELECT e.*, f.name, f.host, f.sev, COALESCE(r.display_name,r.username) req, COALESCE(a.display_name,a.username) apr FROM exceptions e JOIN findings f ON f.id=e.finding_id
                         LEFT JOIN users r ON r.id=e.requested_by LEFT JOIN users a ON a.id=e.approver_id ORDER BY e.id DESC""").fetchall()
        cols = ["Exception", "Finding ID", "Title", "Severity", "Asset", "Status", "Requested by", "Justification", "Compensating controls", "Approver", "Approved at", "Expires", "Review note"]
        body = [[e["id"], e["finding_id"], e["name"], e["sev"], e["host"], e["status"], e["req"], e["justification"], e["compensating_controls"], e["apr"], e["approved_at"], e["expires_at"], e["review_note"]] for e in q]
        title = "Risk acceptance exceptions"; summary = {"exceptions": len(body), "approved": sum(1 for e in q if e["status"] == "Approved")}
    else: raise KeyError(name)
    return {"name": name, "title": title, "columns": cols, "rows": body, "summary": summary, "meta": meta}

def to_csv(rep):
    b = io.StringIO(); w = csv.writer(b)
    w.writerow([f"# {rep['title']}"]); w.writerow([f"# Generated: {rep['meta']['generated_at']} by {rep['meta']['generated_by']}"]); w.writerow([f"# Filters: {rep['meta']['filters']}"])
    for k, v in rep["summary"].items(): w.writerow([f"# {k}: {v}".replace("\n", " ")])
    w.writerow([f"# Priority scores are internal heuristics, not CVSS. Evidence references are finding IDs / scan IDs."]); w.writerow([])
    w.writerow(rep["columns"])
    for r in rep["rows"]: w.writerow([safe_cell(v) for v in r])
    return b.getvalue().encode("utf-8-sig")

def to_pdf(rep):
    from reportlab.lib.pagesizes import landscape, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Spacer
    from xml.sax.saxutils import escape
    buf = io.BytesIO(); doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=24, bottomMargin=24, title=rep["title"])
    st = getSampleStyleSheet(); small = st["BodyText"].clone("s", fontSize=6.5, leading=8)
    el = [Paragraph(f"VulnTrack Sentinel — {escape(rep['title'])}", st["Title"]),
          Paragraph(escape(f"Generated {rep['meta']['generated_at']} by {rep['meta']['generated_by']} | Filters: {rep['meta']['filters']}"), st["BodyText"])]
    el.append(Paragraph(escape(" | ".join(f"{k}: {v}" for k, v in rep["summary"].items())), st["BodyText"]))
    el.append(Paragraph("Priority scores are internal and explainable; they are not CVSS scores.", small)); el.append(Spacer(1, 8))
    data_ = [[Paragraph(f"<b>{escape(str(h))}</b>", small) for h in rep["columns"]]] + [[Paragraph(escape(str("" if v is None else v)[:300]), small) for v in r] for r in rep["rows"][:1500]]
    t = Table(data_, repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6ebf3")), ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#b8c2d4")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el.append(t)
    if len(rep["rows"]) > 1500: el.append(Paragraph(f"Truncated: showing 1500 of {len(rep['rows'])} rows. Use CSV for the full set.", small))
    doc.build(el); return buf.getvalue()
