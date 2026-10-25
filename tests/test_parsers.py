import os, pytest
from parsers import parse_any, parse_report, ReportError
S = os.path.join(os.path.dirname(__file__), "..", "samples")
def rd(n, m="rb"): return open(os.path.join(S, n), m).read()
def test_legacy_nmap_unchanged():
    items = parse_any("x.xml", rd("sample_nmap.xml", "r"))
    assert [(i["id"], i["cvss"], i["sev"]) for i in items][0] == ("d9e65ff7b22d1282", 10.0, "Critical") and len(items) == 4
    assert items[0]["owasp"].startswith("A02")
def test_legacy_openvas_csv_unchanged():
    items = parse_any("x.csv", rd("sample_openvas.csv", "r")); assert len(items) == 2 and items[0]["sev"] == "High" and items[0]["cve"] == "CVE-2017-7679"
def test_heuristic_scores_are_labelled_not_cvss():
    r = parse_report("s.xml", rd("sample_nmap.xml")); src = {i["port"]: i["cvss_source"] for i in r["items"]}
    assert src["23/tcp"].startswith("Heuristic") and src["21/tcp"].startswith("Nmap script") and src["80/tcp"] == "None"
def test_openvas_xml():
    x = b'<report><host><ip>10.0.0.9</ip></host><results><result><host>10.0.0.9</host><port>443/tcp</port><severity>9.1</severity><nvt><name>Bad TLS</name><solution>Fix</solution><tags>cvss_base_vector=AV:N/AC:L/Au:N/C:P/I:P/A:P</tags><refs><ref type="cve" id="CVE-2020-1234"/></refs></nvt></result></results></report>'
    r = parse_report("r.xml", x); assert r["source"] == "OpenVAS" and r["items"][0]["cve"] == "CVE-2020-1234" and r["items"][0]["cvss_vector"].startswith("AV:N") and r["hosts"] == ["10.0.0.9"]
def test_csv_rejected_rows_counted():
    r = parse_report("r.csv", b"IP,NVT Name,CVSS\n10.0.0.1,Good,5.0\n10.0.0.1,,5.0\n"); assert len(r["items"]) == 1 and r["rejected"] == 1
@pytest.mark.parametrize("name,raw,msg", [("a.exe", b"MZ", "unsupported"), ("a.xml", b"", "empty"), ("a.xml", b"\x00\x01binary", "binary"), ("a.xml", b"<nmaprun><host>", "malformed"),
    ("a.xml", b"just text", "not XML"), ("a.csv", b"foo,bar\n1,2", "not recognised"), ("a.xml", b"<root/>", "neither"), ("a.csv", b"<html><script>", "markup"), ("a.xml", b"\xff\xfe\x00bad", "binary")])
def test_malformed_rejected_with_clear_message(name, raw, msg):
    with pytest.raises(ReportError) as e: parse_report(name, raw)
    assert msg in str(e.value)
def test_oversized_rejected():
    with pytest.raises(ReportError, match="exceeds"): parse_report("a.csv", b"IP,NVT Name\n" + b"x" * 200, max_bytes=100)
def test_xxe_and_entity_bombs_blocked():
    xxe = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun><host><address addr="1.1.1.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="1"><state state="open"/><service name="&x;"/></port></ports></host></nmaprun>'
    with pytest.raises(ReportError, match="blocked"): parse_report("a.xml", xxe)
    bomb = b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;">]><nmaprun>&b;</nmaprun>'
    with pytest.raises(ReportError): parse_report("a.xml", bomb)
