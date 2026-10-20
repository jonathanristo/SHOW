#!/usr/bin/env python3
"""tests/unit_normalize.py — unit tests for scripts/normalize.py (pure, no docker)."""
import importlib.util
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("norm", os.path.join(ROOT, "scripts", "normalize.py"))
N = importlib.util.module_from_spec(spec)
spec.loader.exec_module(N)

P = F = 0


def eq(label, got, want):
    global P, F
    if got == want:
        P += 1; print(f"    ✓ {label}")
    else:
        F += 1; print(f"    ✗ {label} — got {got!r} want {want!r}")


print("[unit:normalize]")
# port_from_url (IPv4 / default scheme / bracketed IPv6)
eq("port_from_url ipv4 explicit", N.port_from_url("http://10.0.0.1:8080"), 8080)
eq("port_from_url https default", N.port_from_url("https://10.0.0.1"), 443)
eq("port_from_url ipv6 bracket", N.port_from_url("https://[2001:db8::1]:443"), 443)
# CPE 2.2 -> 2.3
eq("cpe22->23", N.cpe22_to_23("cpe:/a:nginx:nginx:1.25"), "cpe:2.3:a:nginx:nginx:1.25:*:*:*:*:*:*:*")
eq("cpe23 passthrough", N.cpe22_to_23("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"), "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*")
# is_private (v4 private/public, v6 ULA)
eq("is_private v4 private", N.is_private_ip("10.0.0.1"), True)
eq("is_private v4 public", N.is_private_ip("8.8.8.8"), False)
eq("is_private v6 ULA", N.is_private_ip("fd00::1"), True)
# severity mapping
eq("severity CRITICAL", N.severity_norm("CRITICAL"), "critical")
eq("severity unknown->info", N.severity_norm("bogus"), "info")
# nuclei category
eq("category cve->vulnerability", N.nuclei_category("CVE-1", [], "t", "high"), "vulnerability")
eq("category info->information", N.nuclei_category(None, ["tech"], "t", "info"), "information")
# envelope: bracket strip + host_context join
cfg = {"scan_id": "x", "observed_at": "x",
       "host_ctx": {"10.0.0.5": {"hostname": "web.corp", "resolvable": True}}}
eq("envelope strips IPv6 brackets", N.envelope(cfg, "httpx", ip="[2001:db8::9]")["ip_at_observation_time"], "2001:db8::9")
e = N.envelope(cfg, "httpx", ip="10.0.0.5")
eq("envelope host_context hostname", e["hostname_at_observation_time"], "web.corp")
eq("envelope host_context resolvable", e["hostname_resolvable"], True)
eq("envelope IP-only -> null hostname", N.envelope(cfg, "httpx", ip="10.9.9.9")["hostname_resolvable"], None)
# parse_masscan v4 + v6
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "masscan.list"), "w") as fh:
        fh.write("open tcp 80 10.0.0.1 1\nopen tcp 443 2001:db8::1 1\n")
    m = N.parse_masscan(d)
    eq("parse_masscan v4", ("10.0.0.1", 80, "tcp") in m, True)
    eq("parse_masscan v6", ("2001:db8::1", 443, "tcp") in m, True)

# testssl_findings: IPv6 matched_at must be bracketed (2001:db8::1:443 is ambiguous); v4 stays bare
tcfg = {"scan_id": "x", "observed_at": "x", "host_ctx": {}}
with tempfile.TemporaryDirectory() as d:
    tj = os.path.join(d, "testssl.json")
    with open(tj, "w") as fh:
        fh.write('[{"id":"BREACH","ip":"2001:db8::1/2001:db8::1","port":"443","severity":"MEDIUM","finding":"gzip"}]')
    f6 = list(N.testssl_findings(d, tcfg))
    eq("testssl matched_at brackets IPv6", f6[0]["matched_at"], "[2001:db8::1]:443")
    with open(tj, "w") as fh:
        fh.write('[{"id":"BREACH","ip":"10.0.0.5/10.0.0.5","port":"443","severity":"MEDIUM","finding":"gzip"}]')
    f4 = list(N.testssl_findings(d, tcfg))
    eq("testssl matched_at leaves IPv4 bare", f4[0]["matched_at"], "10.0.0.5:443")

# parse_nmap_xml: only open ports enter the services stream (closed/filtered dropped)
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "nmap.xml"), "w") as fh:
        fh.write('<nmaprun><host><address addr="10.0.0.7" addrtype="ipv4"/><ports>'
                 '<port protocol="tcp" portid="80"><state state="open"/></port>'
                 '<port protocol="tcp" portid="81"><state state="closed"/></port>'
                 '<port protocol="tcp" portid="82"><state state="filtered"/></port>'
                 '</ports></host></nmaprun>')
    nm = N.parse_nmap_xml(d)
    eq("parse_nmap_xml keeps open port",     ("10.0.0.7", 80, "tcp") in nm, True)
    eq("parse_nmap_xml drops closed port",   ("10.0.0.7", 81, "tcp") in nm, False)
    eq("parse_nmap_xml drops filtered port", ("10.0.0.7", 82, "tcp") in nm, False)

# read_jsonl flags a tool on malformed AND valid-JSON-wrong-shape rows (array/string), still yields good
# dict rows, and never lets a non-dict reach the callers (which would AttributeError → normalize_failed)
N.PARSE_ERRORS.clear()
with tempfile.TemporaryDirectory() as d:
    p = os.path.join(d, "httpx.json")
    with open(p, "w") as fh:
        fh.write('{"url":"http://x:80"}\n{bad json}\n["array-row"]\n"string-row"\n')
    rows = list(N.read_jsonl(p))
    eq("read_jsonl yields only valid dict rows",         len(rows), 1)
    eq("read_jsonl all rows are dicts",                  all(isinstance(r, dict) for r in rows), True)
    eq("read_jsonl flags bad/wrong-shape rows degraded", "httpx" in N.PARSE_ERRORS, True)
N.PARSE_ERRORS.clear()

# parse_nmap_xml on corrupt XML flags the tool degraded (not a silent empty result)
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "nmap.xml"), "w") as fh:
        fh.write('<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/><ports><port ')  # truncated
    N.parse_nmap_xml(d)
    eq("parse_nmap_xml flags corrupt XML degraded", "nmap" in N.PARSE_ERRORS, True)
N.PARSE_ERRORS.clear()

# shots_map normalizes any gowitness path form to a single repo-relative screenshots/<name>
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "gowitness.jsonl"), "w") as fh:
        fh.write('{"url":"http://a","file_name":"a.png"}\n')
        fh.write('{"url":"http://b","file_name":"screenshots/b.png"}\n')
        fh.write('{"url":"http://c","file_name":"/data/out/TS/screenshots/c.png"}\n')
    sm = N.shots_map(d)
    eq("shots_map: bare name",          sm.get("http://a"), "screenshots/a.png")
    eq("shots_map: strips dup prefix",  sm.get("http://b"), "screenshots/b.png")
    eq("shots_map: strips abs path",    sm.get("http://c"), "screenshots/c.png")

# host_from_httpx: the ip field must never carry a :port (prefer the URL hostname)
eq("host_from_httpx: v4 host:port",      N.host_from_httpx({"host": "10.0.0.1:80"}), "10.0.0.1")
eq("host_from_httpx: from url",          N.host_from_httpx({"url": "http://10.0.0.1:80"}), "10.0.0.1")
eq("host_from_httpx: v6 bracketed url",  N.host_from_httpx({"url": "https://[2001:db8::1]:443"}), "2001:db8::1")
eq("host_from_httpx: v6 bracketed host", N.host_from_httpx({"host": "[2001:db8::1]:443"}), "2001:db8::1")
eq("host_from_httpx: bare v6 host kept", N.host_from_httpx({"host": "2001:db8::1"}), "2001:db8::1")

# load_testssl: a valid-JSON but unrecognized shape degrades testssl (not a silent empty result)
N.PARSE_ERRORS.clear()
with tempfile.TemporaryDirectory() as d:
    with open(os.path.join(d, "testssl.json"), "w") as fh:
        fh.write('{"scanResult":"oops"}')
    rows = N.load_testssl(d)
    eq("load_testssl unrecognized shape → empty",    rows, [])
    eq("load_testssl unrecognized shape → degraded", "testssl" in N.PARSE_ERRORS, True)
N.PARSE_ERRORS.clear()

# load_testssl: a recognized list whose rows aren't testssl records is unusable → degrade; empty list is clean
for _shape, _want in [('["oops"]', True), ('[{"foo":"bar"}]', True),
                      ('[]', False), ('[{"id":"BREACH","severity":"MEDIUM"}]', False),
                      ('[{"id":"BREACH","severity":"MEDIUM"}, "junk"]', True)]:   # mixed: one junk row degrades
    N.PARSE_ERRORS.clear()
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "testssl.json"), "w") as fh:
            fh.write(_shape)
        N.load_testssl(d)
        eq(f"load_testssl degrade={_want} for {_shape}", "testssl" in N.PARSE_ERRORS, _want)
N.PARSE_ERRORS.clear()

print(f"  → {P} passed, {F} failed")
sys.exit(0 if F == 0 else 1)
