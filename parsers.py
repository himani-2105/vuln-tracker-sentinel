"""Parsers for Nmap XML and OpenVAS/GVM (CSV + XML) reports -> normalised findings with CVSS severity and OWASP mapping."""
import re, csv, io, hashlib
from defusedxml import ElementTree as ET
RISKY={21:(5.0,"Disable FTP; use SFTP/FTPS."),23:(7.5,"Disable Telnet; use SSH with key auth."),135:(5.0,"Block RPC from untrusted networks."),139:(5.0,"Disable NetBIOS or firewall it."),445:(6.5,"Restrict SMB, disable SMBv1, patch."),3389:(6.0,"Put RDP behind VPN/NLA and enforce MFA."),5900:(6.0,"Restrict VNC; tunnel over SSH/VPN."),3306:(5.0,"Do not expose databases; bind to localhost/VPN."),5432:(5.0,"Do not expose databases; restrict by firewall."),1433:(5.0,"Do not expose databases; restrict by firewall."),27017:(6.0,"Enable auth; restrict MongoDB network access."),6379:(6.0,"Enable auth; bind Redis to localhost.")}
OW=[(r"sql|inject|xss|cross-site scripting|command exec","A03 Injection"),(r"ssl|tls|cipher|certificate|cleartext|plaintext|telnet|ftp|weak crypto","A02 Cryptographic Failures"),(r"default (password|cred)|credential|brute|weak password|authentication","A07 Identification & Auth Failures"),(r"outdated|end of life|eol|unsupported|version|cve-","A06 Vulnerable & Outdated Components"),(r"traversal|idor|access control|authori[sz]ation|privilege","A01 Broken Access Control"),(r"ssrf","A10 SSRF"),(r"misconfig|directory listing|header|exposed|information disclosure|banner|open port|smb|rdp|vnc","A05 Security Misconfiguration")]
def owasp(t):
    return next((l for r,l in OW if re.search(r,t,re.I)),"-")
def sev(s): return "Critical" if s>=9 else "High" if s>=7 else "Medium" if s>=4 else "Low" if s>0 else "Info"
CVE_RE=r"CVE-\d{4}-\d{4,7}"
def mk(host,port,name,cvss,rem,src,ctx,cvss_source="Scanner reported",evidence="",hostname="",vector="",service=""):
    """Legacy keys are unchanged. Added: cve, cvss_source, evidence, hostname, cvss_vector, service."""
    cves=sorted(set(re.findall(CVE_RE,name+" "+ctx)))
    return dict(id=hashlib.sha1(f"{host}|{port}|{name}".encode()).hexdigest()[:16],host=host,port=port,name=name,cvss=float(cvss),sev=sev(float(cvss)),rem=rem,src=src,owasp=owasp(name+" "+ctx),
        cve=", ".join(cves[:10]),cvss_source=cvss_source if float(cvss)>0 or cvss_source.startswith("Heuristic") else "None",
        evidence=(evidence or ctx or "")[:4000],hostname=hostname,cvss_vector=vector,service=service)
def parse_nmap(text,stats=None):
    out=[]; st_=stats if stats is not None else {}
    st_.setdefault("hosts",set()); st_.setdefault("rows",0); st_.setdefault("rejected",0)
    for h in ET.fromstring(text).iter("host"):
        ad=[a for a in h.findall("address") if a.get("addrtype")=="ipv4"] or h.findall("address")
        host=ad[0].get("addr") if ad else "?"
        hn=h.find("hostnames/hostname"); hname=hn.get("name") if hn is not None else ""
        hs=h.find("status")
        if host=="?": st_["rejected"]+=1; continue
        if hs is None or hs.get("state","up")=="up": st_["hosts"].add(host)
        for p in h.iter("port"):
            st=p.find("state")
            if st is None or st.get("state")!="open": continue
            sv=p.find("service"); port=p.get("portid")
            svn=" ".join(filter(None,[sv.get(k) for k in("name","product","version")])) if sv is not None else "unknown"
            txt=" ".join(s.get("output","") for s in p.findall("script"))
            cves=sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}",txt)))
            scores=[float(m) for m in re.findall(r"CVE-\d{4}-\d{4,7}\s+(\d{1,2}\.\d)",txt)]
            risky=RISKY.get(int(port))
            cvss=max(scores) if scores else (risky[0] if risky else 0.0)
            rem="Patch/upgrade to a fixed version; review vendor advisories." if cves else (risky[1] if risky else "Confirm the service is required; restrict access with a firewall.")
            name=f"Open {svn}"+(f" ({', '.join(cves[:4])}{'...' if len(cves)>4 else ''})" if cves else "")
            csrc="Nmap script output (vulners)" if scores else ("Heuristic estimate (not CVSS)" if risky else "None")
            st_["rows"]+=1
            out.append(mk(host,f"{port}/{p.get('protocol')}",name,cvss,rem,"Nmap",svn+" "+txt+(" open port" if risky else ""),cvss_source=csrc,evidence=f"{svn}\n{txt}".strip(),hostname=hname,service=svn))
    return out
def parse_openvas_csv(text,stats=None):
    out=[]; st_=stats if stats is not None else {}
    st_.setdefault("hosts",set()); st_.setdefault("rows",0); st_.setdefault("rejected",0)
    for r in csv.DictReader(io.StringIO(text)):
        st_["rows"]+=1
        r={(k or "").strip().lower():(v or "").strip() for k,v in r.items()}
        g=lambda *n:next((r[x] for x in n if r.get(x)),"")
        name=g("nvt name","name")
        if not name: st_["rejected"]+=1; continue
        try: cv=float(g("cvss"))
        except ValueError: cv=0.0
        cves=g("cves"); port=g("port") or "general"
        if g("port protocol"): port+="/"+g("port protocol")
        hostv=g("ip","host") or "?"
        if hostv=="?": st_["rejected"]+=1; continue
        st_["hosts"].add(hostv)
        out.append(mk(hostv,port,name+(f" ({cves[:60]})" if cves else ""),cv,g("solution") or "See vendor advisory.","OpenVAS",g("summary"),cvss_source="OpenVAS reported" if cv>0 else "None",evidence=g("summary"),hostname=g("hostname"),service=g("port protocol")))
    return out
def parse_openvas_xml(text,stats=None):
    out=[]; st_=stats if stats is not None else {}
    st_.setdefault("hosts",set()); st_.setdefault("rows",0); st_.setdefault("rejected",0)
    root=ET.fromstring(text)
    for hh in root.iter("host"):
        ip=(hh.findtext("ip") or "").strip()
        if ip: st_["hosts"].add(ip)
    for r in root.iter("result"):
        st_["rows"]+=1
        name=(r.findtext("nvt/name") or r.findtext("name") or "").strip()
        if not name: st_["rejected"]+=1; continue
        try: cv=float(r.findtext("severity") or r.findtext("nvt/cvss_base") or 0)
        except ValueError: cv=0.0
        cves=[x.get("id") for x in r.iter("ref") if x.get("type")=="cve"][:4]
        host=((r.findtext("host") or "?").strip().split() or ["?"])[0]
        vm=re.search(r"cvss_base_vector=([^|\s]+)",r.findtext("nvt/tags") or "")
        st_["hosts"].add(host)
        out.append(mk(host,(r.findtext("port") or "general").strip(),name+(f" ({', '.join(cves)})" if cves else ""),cv,(r.findtext("nvt/solution") or "See vendor advisory.").strip(),"OpenVAS",r.findtext("description") or "",cvss_source="OpenVAS reported" if cv>0 else "None",evidence=r.findtext("description") or "",vector=vm.group(1) if vm else ""))
    return out
def parse_any(filename,text):
    if filename.lower().endswith(".csv"): return parse_openvas_csv(text)
    return parse_nmap(text) if "<nmaprun" in text[:4000] else parse_openvas_xml(text)

class ReportError(ValueError):
    """Raised with a user-readable message when an upload is rejected."""
ALLOWED_EXT=(".xml",".csv")
CSV_HINTS={"nvt name","name","ip","host","cvss","severity"}
def parse_report(filename,raw,max_bytes=25*1024*1024):
    """Validate + parse an uploaded report. Returns dict(items,rejected,rows,hosts,source,warnings). Never executes content."""
    fn=(filename or "").lower()
    if not fn.endswith(ALLOWED_EXT): raise ReportError("unsupported file type (only .xml and .csv are accepted)")
    if not raw: raise ReportError("file is empty")
    if len(raw)>max_bytes: raise ReportError(f"file exceeds the {max_bytes//1048576} MB limit")
    if b"\x00" in raw[:8192]: raise ReportError("file looks binary, not a text report")
    try: text=raw.decode("utf-8-sig")
    except UnicodeDecodeError: raise ReportError("file is not valid UTF-8 text")
    stats={"hosts":set(),"rows":0,"rejected":0}
    try:
        if fn.endswith(".csv"):
            head=text.lstrip()[:2000].split("\n",1)[0].lower()
            if "<" in head[:5]: raise ReportError("file has a .csv extension but contains markup")
            if not any(h in head for h in CSV_HINTS): raise ReportError("CSV header not recognised (expected OpenVAS/GVM columns such as IP, NVT Name, CVSS)")
            items,source=parse_openvas_csv(text,stats),"OpenVAS"
        else:
            if not text.lstrip().startswith("<"): raise ReportError("file has an .xml extension but is not XML")
            if "<nmaprun" in text[:4000]: items,source=parse_nmap(text,stats),"Nmap"
            elif "<result" in text: items,source=parse_openvas_xml(text,stats),"OpenVAS"
            else: raise ReportError("XML is neither an Nmap run nor an OpenVAS/GVM report")
    except ReportError: raise
    except ET.ParseError as e: raise ReportError(f"malformed XML: {e}")
    except Exception as e:
        if type(e).__name__ in ("EntitiesForbidden","DTDForbidden","ExternalReferenceForbidden"): raise ReportError("XML uses DTD/entity features that are blocked for safety")
        raise ReportError(f"could not parse report ({type(e).__name__})")
    if not items and stats["rows"]==0 and not stats["hosts"]: raise ReportError("no findings or hosts found in report")
    return dict(items=items,rejected=stats["rejected"],rows=stats["rows"],hosts=sorted(stats["hosts"]),source=source)
