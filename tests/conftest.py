import os, sys, secrets, pytest
os.environ["VULNTRACK_NO_AUTOAPP"] = "1"; os.environ["VULNTRACK_DISABLE_RATELIMIT"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as appmod, db, security

NMAP = """<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports></host></nmaprun>"""
def nmap_xml(ip, *ports):
    p = "".join(f'<port protocol="tcp" portid="{n}"><state state="open"/><service name="{s}" product="{pr}" version="{v}"/>' + (f'<script id="vulners" output="{cve} {sc} https://x"/>' if cve else "") + "</port>" for n, s, pr, v, cve, sc in ports)
    return NMAP.format(ip=ip, ports=p).encode()
FTP = (21, "ftp", "vsftpd", "2.3.4", "CVE-2011-2523", "10.0"); HTTP = (80, "http", "Apache httpd", "2.2.8", "CVE-2017-7679", "9.8"); TEL = (23, "telnet", "", "", "", "")

class Client:
    def __init__(self, app): self.c = app.test_client(); self.csrf = None; self.user = None
    def login(self, user, pw):
        self.csrf = self.c.get("/api/auth/me").get_json()["csrf"]
        r = self.c.post("/api/auth/login", json={"username": user, "password": pw}, headers={"X-CSRF-Token": self.csrf})
        if r.status_code == 200: self.csrf = r.get_json()["csrf"]
        return r
    def _h(self, h=None): return {"X-CSRF-Token": self.csrf or "", **(h or {})}
    def get(self, u, **k): return self.c.get(u, **k)
    def post(self, u, **k): k["headers"] = self._h(k.get("headers")); return self.c.post(u, **k)
    def patch(self, u, **k): k["headers"] = self._h(k.get("headers")); return self.c.patch(u, **k)
    def put(self, u, **k): k["headers"] = self._h(k.get("headers")); return self.c.put(u, **k)
    def delete(self, u, **k): k["headers"] = self._h(k.get("headers")); return self.c.delete(u, **k)
    def upload(self, name, raw, **form):
        import io; return self.post("/api/upload", data={"files": (io.BytesIO(raw), name), **form}, content_type="multipart/form-data")

@pytest.fixture()
def env(tmp_path):
    app = appmod.create_app({"DB_PATH": str(tmp_path / "t.db"), "SECRET_KEY": secrets.token_hex(32), "TESTING": True})
    pw = {r: secrets.token_urlsafe(16) for r in ("admin", "analyst", "analyst2", "owner", "owner2", "auditor")}
    c = db.connect(str(tmp_path / "t.db"))
    with db.tx(c):
        for n, p in pw.items():
            role = "analyst" if n.startswith("analyst") else "owner" if n.startswith("owner") else n
            c.execute("INSERT INTO users(username,display_name,role,password_hash,created_at) VALUES(?,?,?,?,?)", (n, n, role, security.hash_pw(p), db.now_iso()))
    c.close()
    def client(name): 
        cl = Client(app); r = cl.login(name, pw[name]); assert r.status_code == 200, r.get_json(); return cl
    class E: pass
    e = E(); e.app = app; e.client = client; e.pw = pw; e.path = str(tmp_path / "t.db")
    e.db = lambda: db.connect(e.path)
    return e
