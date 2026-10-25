"""Append-only audit log with a hash chain.
LIMITATION: SQLite triggers + the chain make casual edits fail and tampering *detectable*, but anyone with write access to the
DB file can rebuild the chain. This is NOT cryptographically immutable; ship events to external WORM/SIEM storage for that."""
import json, hashlib
from db import now_iso
SENSITIVE = ("password", "secret", "token", "hash", "csrf", "cookie", "authorization")
def _clean(v):
    if isinstance(v, dict): return {k: ("[redacted]" if any(s in k.lower() for s in SENSITIVE) else _clean(x)) for k, x in v.items()}
    if isinstance(v, (list, tuple)): return [_clean(x) for x in v]
    if isinstance(v, str) and len(v) > 500: return v[:500] + "…"
    return v
def log(c, actor, action, object_type=None, object_id=None, before=None, after=None, ip=None):
    """Call inside the caller's transaction so the event commits atomically with the change."""
    a = actor or {}
    prev = c.execute("SELECT hash FROM audit_events ORDER BY id DESC LIMIT 1").fetchone()
    prev = prev[0] if prev else ""
    at = now_iso()
    b = json.dumps(_clean(before), sort_keys=True, default=str) if before is not None else None
    f = json.dumps(_clean(after), sort_keys=True, default=str) if after is not None else None
    body = json.dumps([prev, at, a.get("id"), a.get("username"), action, object_type, str(object_id) if object_id is not None else None, b, f])
    h = hashlib.sha256(body.encode()).hexdigest()
    c.execute("INSERT INTO audit_events(at,actor_id,actor_name,role,action,object_type,object_id,before_json,after_json,ip,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
              (at, a.get("id"), a.get("username"), a.get("role"), action, object_type, str(object_id) if object_id is not None else None, b, f, ip, prev, h))
def verify_chain(c):
    prev = ""; n = 0
    for r in c.execute("SELECT * FROM audit_events ORDER BY id"):
        body = json.dumps([prev, r["at"], r["actor_id"], r["actor_name"], r["action"], r["object_type"], r["object_id"], r["before_json"], r["after_json"]])
        if r["prev_hash"] != prev or hashlib.sha256(body.encode()).hexdigest() != r["hash"]: return {"ok": False, "broken_at": r["id"], "checked": n}
        prev = r["hash"]; n += 1
    return {"ok": True, "checked": n}
