"""Explainable risk prioritisation. See docs/SCORING.md for the formula, weights and limitations.
The result is an INTERNAL PRIORITY SCORE (0-100). It is not a CVSS score and must never be presented as one."""
import datetime as dt
DEFAULT_WEIGHTS = {"cvss": 0.40, "criticality": 0.20, "exposure": 0.15, "exploit": 0.15, "sla": 0.05, "business": 0.05}
CRIT = {"Critical": 1.0, "High": 0.75, "Medium": 0.5, "Low": 0.25}
EXPO = {"Internet-facing": 1.0, "Internal": 0.3}                       # "Unknown" => missing evidence
BUS = {"Mission-critical": 1.0, "Important": 0.6, "Supporting": 0.3}  # "Unrated" => missing evidence
EXPL = {"Known exploited (KEV)": 1.0, "Exploit confirmed (evidence)": 1.0, "Public exploit reference": 0.7, "None known": 0.0}
EXPLOIT_VALUES = list(EXPL) + ["Unknown"]
TRUSTED_CVSS = ("OpenVAS reported", "Nmap script output", "NVD", "Vendor", "Analyst-entered")
THRESH = [(75, "Critical"), (55, "High"), (35, "Medium"), (0, "Low")]
OPEN_STATES = ("Open", "Triaged", "In Progress", "Fixed — Pending Verification", "Reopened")

def cvss_usable(f): return (f.get("cvss_source") or "").startswith(TRUSTED_CVSS) and f.get("cvss") is not None
def sla_state(f, today):
    """returns (days_remaining|None, overdue bool). Closed/accepted findings are never overdue."""
    if not f.get("due_date") or f.get("status") not in OPEN_STATES: return None, False
    left = (dt.date.fromisoformat(f["due_date"][:10]) - today).days
    return left, left < 0

def assess(f, a, weights=None, kev=frozenset(), today=None):
    w = weights or DEFAULT_WEIGHTS; today = today or dt.date.today()
    a = a or {}; comps = {}; factors = []; missing = []
    # 1 CVSS
    if cvss_usable(f):
        comps["cvss"] = min(max(float(f["cvss"]), 0), 10) / 10
        if f["cvss"] >= 7: factors.append(f"CVSS {f['cvss']:.1f}, source: {f['cvss_source']} (not independently verified against NVD)")
    else:
        src = f.get("cvss_source") or "none"
        missing.append("No scanner-reported CVSS score" + (" (value shown is a heuristic estimate, not CVSS)" if src.startswith("Heuristic") else ""))
    # 2 criticality
    if a.get("criticality") in CRIT:
        comps["criticality"] = CRIT[a["criticality"]]
        if a["criticality"] in ("Critical", "High"): factors.append(f"Asset criticality is {a['criticality']}")
    else: missing.append("Asset criticality not set")
    # 3 exposure
    if a.get("internet_exposure") in EXPO:
        comps["exposure"] = EXPO[a["internet_exposure"]]
        if a["internet_exposure"] == "Internet-facing": factors.append("Asset is marked Internet-facing" + (f" ({a.get('exposure_source')})" if a.get("exposure_source") else ""))
    else: missing.append("Internet exposure not established")
    # 4 exploit evidence (KEV catalogue match is evidence; absence of a catalogue match is not)
    ex = f.get("exploit_status") or "Unknown"
    cves = [c.strip() for c in (f.get("cve") or "").split(",") if c.strip()]
    if any(c in kev for c in cves): ex = "Known exploited (KEV)"
    if ex in EXPL:
        comps["exploit"] = EXPL[ex]
        if EXPL[ex] > 0: factors.append(f"Exploit evidence: {ex}")
    else: missing.append("Exploit status unknown (no KEV match or analyst determination)")
    # 5 SLA pressure
    left, overdue = sla_state(f, today)
    if f.get("due_date") and f.get("status") in OPEN_STATES:
        try:
            first = dt.datetime.fromisoformat(f["first_seen"]).date(); span = max((dt.date.fromisoformat(f["due_date"][:10]) - first).days, 1)
            comps["sla"] = 1.0 if overdue else min(max(1 - left / span, 0), 1)
        except Exception: comps["sla"] = 1.0 if overdue else 0.0
        if overdue: factors.append(f"SLA breached {-left} day(s) ago")
        elif left is not None and left <= 7: factors.append(f"SLA deadline in {left} day(s)")
    else: missing.append("No SLA deadline (finding closed or not yet scheduled)") if f.get("status") in OPEN_STATES else None
    # 6 business importance
    if a.get("business_importance") in BUS:
        comps["business"] = BUS[a["business_importance"]]
        if a["business_importance"] == "Mission-critical": factors.append("Asset supports a mission-critical business function")
    else: missing.append("Business importance not set")
    known_w = sum(w[k] for k in comps)
    score = round(100 * sum(w[k] * v for k, v in comps.items()) / known_w, 1) if known_w else None
    confidence_ratio = round(known_w / sum(w.values()), 2)
    confidence = "High" if confidence_ratio >= 0.85 else "Medium" if confidence_ratio >= 0.6 else "Low"
    complete = "cvss" in comps and not [m for m in missing if not m.startswith("No SLA")]
    category = next((n for t, n in THRESH if score is not None and score >= t), "Incomplete") if "cvss" in comps else "Incomplete"
    if "cvss" in comps and comps.get("exploit", 0) >= 1.0 and f["cvss"] >= 7 and category in ("Medium", "Low"):
        category = "High"; factors.append("Floor rule: confirmed exploitation with CVSS >= 7 is never rated below High")
    return {"score": score, "category": category, "provisional": "cvss" not in comps, "confidence": confidence, "confidence_ratio": confidence_ratio,
            "complete": complete, "components": {k: round(v, 2) for k, v in comps.items()}, "factors": factors, "missing": missing,
            "next_action": next_action(f, a, category, missing, overdue, left, ex)}

def next_action(f, a, cat, missing, overdue, left, ex):
    st = f.get("status")
    if st == "Fixed — Pending Verification": return "Verify the fix: re-scan the asset with the same scanner, or attach independent verification evidence."
    if st == "Risk Accepted": return "Keep the exception under review and re-assess before it expires."
    if st == "Verified Resolved": return "No action. Monitor future scans for recurrence."
    if st == "Reopened": return "Re-triage: the issue returned or an exception lapsed. Assign an owner and confirm a remediation date."
    if overdue: return f"Escalate: SLA breached {-left} day(s) ago. Fix, mitigate, or request a time-boxed risk exception."
    if ex in ("Known exploited (KEV)", "Exploit confirmed (evidence)"): return "Patch or mitigate immediately; exploitation evidence exists."
    if not f.get("owner_id") and cat in ("Critical", "High"): return "Assign a remediation owner now; this is high priority with no owner."
    if any(m.startswith("No scanner-reported CVSS") for m in missing): return "Obtain a scanner-reported or NVD CVSS score; priority is provisional until then."
    if any("criticality" in m or "exposure" in m for m in missing): return "Set asset criticality and exposure to raise assessment confidence."
    if left is not None and left <= 7: return f"Complete remediation within {max(left,0)} day(s) to stay within SLA."
    return "Plan remediation before the SLA deadline." if f.get("due_date") else "Triage and schedule remediation."
