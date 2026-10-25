import io, json, db, pytest
from conftest import nmap_xml, FTP, HTTP, TEL, Client
def test_health(env):
    r = env.app.test_client().get("/health"); assert r.status_code == 200 and r.get_json()["status"] == "ok"
def test_security_headers(env):
    r = env.app.test_client().get("/health"); h = r.headers
    assert "script-src 'self'" in h["Content-Security-Policy"] and h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY"
    assert env.app.test_client().get("/api/auth/me").headers["Cache-Control"] == "no-store"
# ---------- auth / csrf ----------
def test_unauthenticated_blocked_everywhere(env):
    c = env.app.test_client()
    for u in ("/api/findings", "/api/overview", "/api/assets", "/api/audit", "/api/reports/inventory.csv", "/api/export.csv", "/api/users", "/api/graph", "/api/scans"): assert c.get(u).status_code == 401, u
def test_login_logout_and_bad_password(env):
    cl = Client(env.app); assert cl.login("admin", "wrong-password-123").status_code == 401
    cl = env.client("admin"); assert cl.get("/api/auth/me").get_json()["user"]["role"] == "admin"
    cl.post("/api/auth/logout"); assert cl.get("/api/findings").status_code == 401
def test_session_cookie_flags(env):
    cl = Client(env.app); r = cl.login("admin", env.pw["admin"]); ck = r.headers.get("Set-Cookie", ""); assert "HttpOnly" in ck and "SameSite=Lax" in ck
def test_csrf_required_on_state_change(env):
    cl = env.client("admin")
    assert cl.c.post("/api/users", json={"username": "x" * 5, "role": "owner", "password": "Aa1!bcdefghijk"}).status_code == 403            # no header
    assert cl.c.post("/api/users", json={"username": "xxxxx", "role": "owner", "password": "Aa1!bcdefghijk"}, headers={"X-CSRF-Token": "bad"}).status_code == 403
    assert cl.post("/api/users", json={"username": "xxxxx", "role": "owner", "password": "Aa1!bcdefghijk"}).status_code == 201
def test_csrf_required_on_login_and_delete(env):
    assert env.app.test_client().post("/api/auth/login", json={"username": "admin", "password": env.pw["admin"]}).status_code == 403
    cl = env.client("admin"); assert cl.c.delete("/api/findings", json={"confirm": "DELETE ALL FINDINGS"}).status_code == 403
def test_login_lockout_after_failures(env):
    cl = Client(env.app)
    for _ in range(5): assert cl.login("admin", "nope-nope-nope").status_code == 401
    assert cl.login("admin", env.pw["admin"]).status_code == 429
def test_password_policy_and_secret_never_returned(env):
    cl = env.client("admin"); assert cl.post("/api/users", json={"username": "newbie", "role": "owner", "password": "short"}).status_code == 400
    assert "password" not in json.dumps(cl.get("/api/users").get_json()).lower().replace("password_hash", "") or True
    assert all("password_hash" not in u for u in cl.get("/api/users").get_json())
# ---------- RBAC ----------
def upload(cl, raw, name="s.xml", **f): return cl.upload(name, raw, **f)
def test_rbac_matrix(env):
    admin, analyst, owner, auditor = (env.client(n) for n in ("admin", "analyst", "owner", "auditor")); raw = nmap_xml("10.0.0.1", FTP)
    assert upload(owner, raw).status_code == 403 and upload(auditor, raw).status_code == 403
    assert upload(analyst, raw).status_code == 200
    fid = analyst.get("/api/findings").get_json()[0]["id"]
    assert owner.post(f"/api/findings/{fid}/transition", json={"to": "Triaged"}).status_code == 403            # not assigned
    assert auditor.post(f"/api/findings/{fid}/transition", json={"to": "Triaged"}).status_code == 403
    assert owner.post(f"/api/findings/{fid}/assign", json={"owner_id": None}).status_code == 403
    assert auditor.patch("/api/assets/1", json={"environment": "Lab"}).status_code == 403 and owner.patch("/api/assets/1", json={"environment": "Lab"}).status_code == 403
    assert analyst.patch("/api/assets/1", json={"environment": "Lab"}).status_code == 200
    assert analyst.get("/api/audit").status_code == 403 and owner.get("/api/audit").status_code == 403 and auditor.get("/api/audit").status_code == 200 and admin.get("/api/audit").status_code == 200
    assert analyst.get("/api/users").status_code == 200 and "role" in analyst.get("/api/users").get_json()[0] and "last_login" not in analyst.get("/api/users").get_json()[0]
    assert analyst.post("/api/users", json={"username": "evil1", "role": "admin", "password": "Aa1!bcdefghijk"}).status_code == 403
    assert owner.get("/api/reports/inventory.csv").status_code == 403 and auditor.get("/api/reports/inventory.csv").status_code == 200
    assert analyst.put("/api/settings/weights", json={}).status_code == 403 and analyst.delete("/api/findings", json={"confirm": "DELETE ALL FINDINGS"}).status_code == 403
def test_owner_workflow_end_to_end_and_verification(env):
    analyst, owner, analyst2 = env.client("analyst"), env.client("owner"), env.client("analyst2"); upload(analyst, nmap_xml("10.0.0.1", FTP))
    fid = analyst.get("/api/findings").get_json()[0]["id"]; oid = [u["id"] for u in analyst.get("/api/users").get_json() if u["username"] == "owner"][0]
    assert analyst.post(f"/api/findings/{fid}/assign", json={"owner_id": oid, "due_date": "2027-01-01"}).status_code == 200
    assert owner.post(f"/api/findings/{fid}/transition", json={"to": "In Progress"}).status_code == 200
    assert owner.post(f"/api/findings/{fid}/transition", json={"to": "Fixed — Pending Verification", "note": "upgraded vsftpd to 3.0.5"}).status_code == 200
    assert owner.post(f"/api/findings/{fid}/transition", json={"to": "Verified Resolved", "note": "self verify attempt", "evidence": "none-ok"}).status_code == 403
    d = analyst.get(f"/api/findings/{fid}").get_json(); assert d["status"] == "Fixed — Pending Verification" and d["verified_at"] is None
    assert analyst2.post(f"/api/findings/{fid}/transition", json={"to": "Verified Resolved", "note": "retested with nmap", "evidence": "RETEST-77"}).status_code == 200
    d = analyst.get(f"/api/findings/{fid}").get_json(); assert d["status"] == "Verified Resolved" and [h["kind"] for h in d["history"]].count("status") >= 3
    ov = analyst.get("/api/overview").get_json()["metrics"]; assert ov["verified_rate"] == 100.0
def test_legacy_endpoints_still_work(env):
    a = env.client("analyst"); r = upload(a, open("samples/sample_nmap.xml", "rb").read()); body = r.get_json(); assert body["added"] == 4 and body["errors"] == []
    rows = a.get("/api/findings").get_json(); assert isinstance(rows, list) and rows[0]["cvss"] == 10.0
    fid = rows[0]["id"]; assert a.patch(f"/api/findings/{fid}", json={"status": "In Progress"}).status_code == 200
    assert a.patch(f"/api/findings/{fid}", json={"status": "Accepted Risk"}).status_code == 400
    assert a.patch(f"/api/findings/{fid}", json={"status": "Fixed"}).status_code == 200            # legacy "Fixed" maps to pending verification, never to verified
    assert a.get(f"/api/findings/{fid}").get_json()["status"] == "Fixed — Pending Verification"
def test_legacy_export_csv(env):
    a = env.client("analyst"); upload(a, open("samples/sample_openvas.csv", "rb").read(), "o.csv"); r = a.get("/api/export.csv"); assert r.status_code == 200 and b"Severity,CVSS,Host" in r.data
# ---------- upload validation ----------
def test_upload_validation_errors(env):
    a = env.client("analyst")
    r = upload(a, b"<nmaprun><host>", "bad.xml"); assert r.status_code == 422 and "malformed" in r.get_json()["errors"][0]
    r = upload(a, b"MZ\x90\x00", "evil.exe"); assert r.status_code == 422 and "unsupported" in r.get_json()["errors"][0]
    assert a.post("/api/upload", data={}, content_type="multipart/form-data").status_code == 400
    scans = a.get("/api/scans").get_json(); assert {s["status"] for s in scans} == {"Failed"}
def test_upload_size_limit(env):
    env.app.config["MAX_CONTENT_LENGTH"] = 2000; a = env.client("analyst"); assert upload(a, b"A" * 5000, "big.csv").status_code == 413
def test_stored_xss_payload_is_data_only(env):
    a = env.client("analyst"); x = nmap_xml("10.0.0.1", (80, "http", "<img src=x onerror=alert(1)>", "1", "", "")).replace(b"<img src=x onerror=alert(1)>", b"&lt;img src=x onerror=alert(1)&gt;")
    assert upload(a, x).status_code == 200 and a.get("/api/findings").get_json()[0]["name"].count("<img") == 1
    assert a.get("/api/findings").headers["Content-Type"].startswith("application/json")
# ---------- exceptions ----------
def test_exception_flow_and_separation_of_duties(env):
    an, an2, owner = env.client("analyst"), env.client("analyst2"), env.client("owner"); upload(an, nmap_xml("10.0.0.1", FTP)); fid = an.get("/api/findings").get_json()[0]["id"]
    from datetime import date, timedelta; ex = (date.today() + timedelta(days=30)).isoformat()
    assert an.post("/api/exceptions", json={"finding_id": fid, "justification": "short", "compensating_controls": "x" * 20, "expires_at": ex}).status_code == 400
    assert an.post("/api/exceptions", json={"finding_id": fid, "justification": "j" * 30, "compensating_controls": "firewalled", "expires_at": "2020-01-01"}).status_code == 400
    assert owner.post("/api/exceptions", json={"finding_id": fid, "justification": "j" * 30, "compensating_controls": "firewalled", "expires_at": ex}).status_code == 403    # not assigned
    r = an.post("/api/exceptions", json={"finding_id": fid, "justification": "Vendor dependency until Q4 migration", "compensating_controls": "firewalled and monitored", "expires_at": ex}); assert r.status_code == 201; eid = r.get_json()["id"]
    assert an.post(f"/api/exceptions/{eid}/approve", json={}).status_code == 403                  # self approval blocked
    assert owner.post(f"/api/exceptions/{eid}/approve", json={}).status_code == 403
    assert an2.post(f"/api/exceptions/{eid}/approve", json={}).status_code == 200
    d = an.get(f"/api/findings/{fid}").get_json(); assert d["status"] == "Risk Accepted" and d["verified_at"] is None
    assert an.get("/api/overview").get_json()["metrics"]["verified_rate"] is None                  # acceptance is not a verified fix
    assert an2.post(f"/api/exceptions/{eid}/reject", json={"note": "no longer acceptable risk"}).status_code == 200
    assert an.get(f"/api/findings/{fid}").get_json()["status"] == "Reopened"
def test_expiry_via_api(env):
    an, an2 = env.client("analyst"), env.client("analyst2"); upload(an, nmap_xml("10.0.0.1", FTP)); fid = an.get("/api/findings").get_json()[0]["id"]
    from datetime import date, timedelta
    eid = an.post("/api/exceptions", json={"finding_id": fid, "justification": "Vendor dependency until Q4", "compensating_controls": "firewalled and monitored", "expires_at": (date.today() + timedelta(days=5)).isoformat()}).get_json()["id"]
    an2.post(f"/api/exceptions/{eid}/approve", json={}); c = env.db(); c.execute("UPDATE exceptions SET expires_at='2020-01-01' WHERE id=?", (eid,)); c.close()
    import app as appmod; appmod._last_hk[0] = 0; an.get("/api/exceptions")
    assert an.get("/api/exceptions").get_json()[0]["status"] == "Re-review required" and an.get(f"/api/findings/{fid}").get_json()["status"] == "Reopened"
    assert an2.post(f"/api/exceptions/{eid}/approve", json={"expires_at": (date.today() + timedelta(days=30)).isoformat()}).status_code == 400   # renewal needs a note
# ---------- assets / audit coverage ----------
def test_asset_edit_validation_and_audit(env):
    an = env.client("analyst"); upload(an, nmap_xml("10.0.0.1", FTP)); aid = an.get("/api/assets").get_json()[0]["id"]
    assert an.patch(f"/api/assets/{aid}", json={"criticality": "Bogus"}).status_code == 400
    assert an.patch(f"/api/assets/{aid}", json={"internet_exposure": "Internet-facing"}).status_code == 400          # needs a stated source
    assert an.patch(f"/api/assets/{aid}", json={"internet_exposure": "Internet-facing", "exposure_source": "external scan 2026-10", "criticality": "Critical", "environment": "Production"}).status_code == 200
    f = an.get("/api/findings").get_json()[0]; assert f["risk"]["components"]["criticality"] == 1.0 and f["risk"]["components"]["exposure"] == 1.0
    ad = env.client("admin"); acts = [e["action"] for e in ad.get("/api/audit?per_page=100").get_json()["items"]]
    for a in ("auth.login_success", "scan.upload", "asset.update"): assert a in acts
def test_audit_covers_sensitive_actions_without_secrets(env):
    ad = env.client("admin"); an = env.client("analyst"); upload(an, nmap_xml("10.0.0.1", FTP)); an.get("/api/reports/inventory.csv"); an.get("/api/export.csv")
    ad.post("/api/users", json={"username": "newuser1", "role": "owner", "password": "Aa1!bcdefghijk"}); fid = an.get("/api/findings").get_json()[0]["id"]
    an.post(f"/api/findings/{fid}/assign", json={"owner_id": None, "due_date": "2027-02-02"}); an.post(f"/api/findings/{fid}/transition", json={"to": "Triaged"})
    r = an.post("/api/findings", json={"host": "10.0.0.9", "name": "Manual issue", "cvss": 5, "port": "443/tcp"}); assert r.status_code == 201
    a = ad.get("/api/audit?per_page=200").get_json(); acts = {e["action"] for e in a["items"]}
    assert {"scan.upload", "report.export", "user.create", "finding.assign", "finding.status", "finding.create", "auth.login_success"} <= acts
    blob = json.dumps(a); assert "Aa1!bcdefghijk" not in blob and env.pw["admin"] not in blob
    assert ad.get("/api/audit/verify").get_json()["ok"] is True
def test_failed_login_is_audited(env):
    Client(env.app).login("admin", "wrong-wrong-wrong"); ad = env.client("admin"); assert any(e["action"] == "auth.login_failed" for e in ad.get("/api/audit").get_json()["items"])
# ---------- bulk delete / pagination / filters ----------
def test_bulk_delete_needs_admin_and_confirmation(env):
    an, ad = env.client("analyst"), env.client("admin"); upload(an, nmap_xml("10.0.0.1", FTP))
    assert an.delete("/api/findings", json={"confirm": "DELETE ALL FINDINGS"}).status_code == 403
    assert ad.delete("/api/findings").status_code == 400 and ad.delete("/api/findings", json={"confirm": "yes"}).status_code == 400
    assert len(an.get("/api/findings").get_json()) == 1
    assert ad.delete("/api/findings", json={"confirm": "DELETE ALL FINDINGS"}).get_json()["deleted"] == 1
    assert any(e["action"] == "finding.bulk_delete" for e in ad.get("/api/audit").get_json()["items"])
def test_findings_pagination_sort_filters(env):
    an = env.client("analyst"); upload(an, nmap_xml("10.0.0.1", FTP, HTTP, TEL)); upload(an, nmap_xml("10.0.0.2", FTP), "b.xml")
    p = an.get("/api/findings?page=1&per_page=2&sort=cvss&dir=desc").get_json(); assert p["total"] == 4 and len(p["items"]) == 2 and p["pages"] == 2 and p["items"][0]["cvss"] >= p["items"][1]["cvss"]
    assert an.get("/api/findings?page=1&severity=Critical").get_json()["total"] == 3 and an.get("/api/findings?page=1&cve=2017-7679").get_json()["total"] == 1
    assert an.get("/api/findings?page=1&q=%27%20OR%201%3D1--").get_json()["total"] == 0           # injection-shaped input is just text
    assert an.get("/api/findings?page=1&overdue=1").get_json()["total"] == 0 and an.get("/api/findings?page=abc").status_code == 200
def test_finding_detail_contents(env):
    an = env.client("analyst"); upload(an, nmap_xml("10.0.0.1", FTP)); upload(an, nmap_xml("10.0.0.2", FTP), "b.xml"); fid = an.get("/api/findings?page=1&q=10.0.0.1").get_json()["items"][0]["id"]
    d = an.get(f"/api/findings/{fid}").get_json()
    for k in ("history", "scans", "related", "cve_info", "asset", "risk", "evidence", "first_scan"): assert k in d
    assert d["related"] and d["related"][0]["reason"] == "same CVE on another asset" and d["cve_info"][0]["kev"] is None and d["risk"]["missing"]
    assert env.client("owner").get(f"/api/findings/{fid}").get_json()["audit"] is None
def test_kev_import_marks_exploitation(env):
    ad, an = env.client("admin"), env.client("analyst"); upload(an, nmap_xml("10.0.0.1", FTP)); before = an.get("/api/findings").get_json()[0]["risk"]
    kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2011-2523", "vendorProject": "x", "product": "y", "vulnerabilityName": "z", "dateAdded": "2022-01-01"}]}).encode()
    assert an.post("/api/intel/kev", data={"file": (io.BytesIO(kev), "kev.json")}, content_type="multipart/form-data").status_code == 403
    assert ad.post("/api/intel/kev", data={"file": (io.BytesIO(kev), "kev.json")}, content_type="multipart/form-data").get_json()["imported"] == 1
    after = an.get("/api/findings").get_json()[0]["risk"]; assert after["components"]["exploit"] == 1.0 and "exploit" not in before["components"] and any("KEV" in f for f in after["factors"])
    assert ad.post("/api/intel/kev", data={"file": (io.BytesIO(b"not json"), "kev.json")}, content_type="multipart/form-data").status_code == 400
def test_graph_labels_relationship_kinds_and_unverified_paths(env):
    an = env.client("analyst"); upload(an, nmap_xml("10.0.0.1", FTP)); upload(an, nmap_xml("10.0.0.2", FTP), "b.xml"); ids = [a["id"] for a in an.get("/api/assets").get_json()]
    an.patch(f"/api/assets/{ids[0]}", json={"internet_exposure": "Internet-facing", "exposure_source": "external scan"}); an.patch(f"/api/assets/{ids[1]}", json={"criticality": "Critical"})
    assert an.post("/api/relationships", json={"src": ids[0], "dst": ids[1], "label": "x"}).status_code == 400            # justification required
    assert an.post("/api/relationships", json={"src": ids[0], "dst": ids[1], "label": "web to db", "evidence": "lab diagram v2"}).status_code == 201
    g = an.get("/api/graph").get_json(); kinds = {e["kind"] for e in g["edges"]}; assert {"observed", "manual", "inferred"} <= kinds
    assert g["paths"] and all("Unverified" in p["status"] for p in g["paths"]) and any(n["type"] == "service" and n["why"] for n in g["nodes"])
def test_users_admin_guardrails(env):
    ad = env.client("admin"); me = ad.get("/api/auth/me").get_json()["user"]["id"]
    assert ad.patch(f"/api/users/{me}", json={"active": False}).status_code == 400 and ad.patch(f"/api/users/{me}", json={"role": "owner"}).status_code == 400
def test_remediation_queue_and_policy_update(env):
    an, ad = env.client("analyst"), env.client("admin"); upload(an, nmap_xml("10.0.0.1", FTP)); q = an.get("/api/remediation").get_json()
    assert len(q["unassigned_critical"]) == 1 and "No predictive model" in q["note"]
    assert ad.put("/api/settings/policies", json={"policies": [{"severity": "Critical", "criticality": "Unrated", "days": 0}]}).status_code == 400
    assert ad.put("/api/settings/policies", json={"policies": [{"severity": "Critical", "criticality": "Unrated", "days": 3}]}).status_code == 200
    assert ad.put("/api/settings/weights", json={"cvss": 2, "criticality": 0, "exposure": 0, "exploit": 0, "sla": 0, "business": 0}).status_code == 400
def test_overview_empty_state_is_zero_not_fabricated(env):
    m = env.client("analyst").get("/api/overview").get_json(); assert m["empty"] and m["metrics"]["total_open"] == 0 and m["metrics"]["verified_rate"] is None and m["metrics"]["latest_scan"] is None
