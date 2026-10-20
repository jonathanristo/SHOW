#!/usr/bin/env python3
"""
SHOW output normalizer — emits sensor-output/1.0 conformant NDJSON streams.

Stdlib only; runs inside the `discovery` container (python3). Reads a run
directory's raw tool artifacts and writes normalized streams. This progressively
replaces the legacy jq/awk merge(): each stream migrates here per Stage 6 of the
plan (6c services, 6d hosts, 6e tls, 6f web_assets detail, 6g findings). Streams
NOT yet migrated are still written by merge() — the normalizer only writes what
it owns, so every stream is produced by exactly one system (no half state).

Owns today:
  web_assets.ndjson   (from httpx.json)

Envelope (sensor-output/1.0 §3) is stamped on every record. See
UNCOVER_docs/uncover_sensor_output_spec_v1.md and show_data_schema.md.
"""
import argparse
import ipaddress
import json
import os
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

MODULE = "SHOW"


# ── helpers ──────────────────────────────────────────────────────────────────
def g(obj, *keys):
    """First present, non-empty-string value among keys (0/False are kept)."""
    for k in keys:
        v = obj.get(k)
        if v is not None and v != "":
            return v
    return None


def load_host_context(run_dir):
    """ip -> {hostname, resolvable} from host_context.tsv (`ip\\thostname\\tresolvable`)."""
    ctx = {}
    p = os.path.join(run_dir, "host_context.tsv")
    if not os.path.exists(p):
        return ctx
    with open(p) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 3:
                continue
            ip, hostname, resolvable = parts[0], parts[1], parts[2]
            r = True if resolvable == "true" else False if resolvable == "false" else None
            if ip:
                ctx[ip] = {"hostname": hostname or None, "resolvable": r}
    return ctx


PARSE_ERRORS = set()   # tools whose output (JSON or nmap XML) couldn't be fully parsed → manifest marks degraded


def read_jsonl(path):
    if not os.path.exists(path):
        return
    tool = os.path.basename(path).split(".")[0]   # httpx.json → httpx, nuclei.jsonl → nuclei
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                PARSE_ERRORS.add(tool)
                continue
            if not isinstance(obj, dict):
                PARSE_ERRORS.add(tool)   # valid JSON but wrong shape (array/string row) — degrade, don't crash
                continue
            yield obj


def envelope(cfg, source_tool, ip=None, hostname=None):
    """sensor-output/1.0 §3 — the common envelope on every record."""
    if ip and ip.startswith("[") and ip.endswith("]"):
        ip = ip[1:-1]                       # normalize bracketed IPv6 → bare literal
    hn, resolvable = hostname, None
    if ip and ip in cfg["host_ctx"]:
        hn = hn or cfg["host_ctx"][ip]["hostname"]
        resolvable = cfg["host_ctx"][ip]["resolvable"]
    return {
        "source_module": MODULE,
        "source_tool": source_tool,
        "scan_id": cfg["scan_id"],
        "observed_at": cfg["observed_at"],
        "ip_at_observation_time": ip or None,
        "hostname_at_observation_time": hn or None,
        "hostname_resolvable": resolvable,
    }


def write_stream(run_dir, name, records, cfg):
    """Write NDJSON; if empty, one sentinel line (spec §2.11). Returns count."""
    path = os.path.join(run_dir, name)
    n = 0
    with open(path, "w") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
            n += 1
        if n == 0:
            fh.write(json.dumps({
                "source_module": MODULE,
                "scan_id": cfg["scan_id"],
                "observed_at": cfg["observed_at"],
                "message": "No records for this stream",
            }) + "\n")
    return n


def shots_map(run_dir):
    """url -> relative screenshot path, from the gowitness manifest."""
    m = {}
    for gw in read_jsonl(os.path.join(run_dir, "gowitness.jsonl")):
        url = gw.get("url")
        f = gw.get("file_name") or gw.get("screenshot")
        if url and f:
            # gowitness may emit a bare name, "screenshots/x.png", or an absolute container path —
            # normalize to a single repo-relative screenshots/<name> (no double "screenshots/" prefix).
            m[url] = "screenshots/" + os.path.basename(f)
    return m


def port_from_url(url):
    if not url:
        return None
    try:
        parts = urlsplit(url)
        if parts.port:
            return parts.port
        return {"http": 80, "https": 443}.get(parts.scheme)
    except ValueError:
        return None


def host_from_httpx(h):
    """Observed IP for an httpx row: prefer urlsplit(url).hostname (strips scheme / [brackets] / :port);
    fall back to .host with an accidental :port removed so ip fields never carry a port."""
    url = h.get("url")
    if url:
        try:
            hn = urlsplit(url).hostname
            if hn:
                return hn
        except ValueError:
            pass
    host = h.get("host") or ""
    if host.startswith("["):
        return host[1:].split("]")[0] or None      # [2001:db8::1]:443 → 2001:db8::1
    if host.count(":") == 1:
        return host.split(":")[0] or None           # 10.0.0.1:80 → 10.0.0.1 (single colon = host:port)
    return host or None


# ── web_assets (from httpx.json) ─────────────────────────────────────────────
def norm_web_assets(run_dir, cfg):
    shots = shots_map(run_dir)
    for h in read_jsonl(os.path.join(run_dir, "httpx.json")):
        ip = host_from_httpx(h)  # prefer the URL hostname; httpx .host may carry a :port
        url = h.get("url")
        tech = [{"name": t, "version": None, "category": None, "confidence": None}
                for t in (h.get("tech") or h.get("technologies") or [])]
        rh = h.get("hash")
        if isinstance(rh, dict):
            rh = rh.get("body_sha256") or rh.get("body_mmh3")
        rec = envelope(cfg, "httpx", ip=ip)
        rec.update({
            "url": url,
            "port": port_from_url(url),
            "status": g(h, "status_code", "status-code"),
            "title": g(h, "title"),
            "server": g(h, "webserver", "web-server", "server"),
            "content_type": g(h, "content_type", "content-type"),
            "content_length": g(h, "content_length", "content-length"),
            "redirect_url": g(h, "location"),
            "tech": tech,
            "response_hash": rh or None,
            "screenshot": shots.get(url),
        })
        yield rec


# ── services (from nmap.xml + masscan.list) ──────────────────────────────────
def cpe22_to_23(cpe):
    """nmap CPE 2.2 URI (cpe:/a:vendor:product:ver) → CPE 2.3 formatted string."""
    if not cpe or cpe.startswith("cpe:2.3:") or not cpe.startswith("cpe:/"):
        return cpe
    parts = cpe[len("cpe:/"):].split(":")
    comps = (parts + ["*"] * 11)[:11]
    return "cpe:2.3:" + ":".join(c if c else "*" for c in comps)


def parse_masscan(run_dir):
    """(ip, port, proto) -> {source_tool} from masscan.list open lines."""
    out = {}
    p = os.path.join(run_dir, "masscan.list")
    if not os.path.exists(p):
        return out
    with open(p) as fh:
        for line in fh:
            f = line.split()
            if len(f) >= 4 and f[0] == "open":
                try:
                    port = int(f[2])
                except ValueError:
                    continue
                out[(f[3], port, f[1])] = {"source_tool": "masscan"}
    return out


def parse_nmap_xml(run_dir):
    """(ip, port, proto) -> enriched service dict, from nmap.xml + nmap6.xml (-oX)."""
    out = {}
    for fn in ("nmap.xml", "nmap6.xml"):
        p = os.path.join(run_dir, fn)
        if not os.path.exists(p):
            continue
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError:
            PARSE_ERRORS.add(fn.split(".")[0])   # nmap.xml → nmap, nmap6.xml → nmap6: corrupt XML degrades the run
            continue
        for host in root.findall("host"):
            ip = next((a.get("addr") for a in host.findall("address")
                       if a.get("addrtype") in ("ipv4", "ipv6")), None)
            ports = host.find("ports")
            if not ip or ports is None:
                continue
            for port in ports.findall("port"):
                proto = port.get("protocol") or "tcp"
                try:
                    pid = int(port.get("portid"))
                except (TypeError, ValueError):
                    continue
                st, svc = port.find("state"), port.find("service")
                state = st.get("state") if st is not None else "open"
                if state != "open":       # services / open-port stream is open ports only — skip closed/filtered
                    continue
                entry = {"source_tool": "nmap",
                         "state": state,
                         "service": None, "product": None, "version": None,
                         "extra_info": None, "cpe": []}
                if svc is not None:
                    entry.update(service=svc.get("name"), product=svc.get("product"),
                                 version=svc.get("version"), extra_info=svc.get("extrainfo"),
                                 cpe=[cpe22_to_23(c.text) for c in svc.findall("cpe") if c.text])
                out[(ip, pid, proto)] = entry
    return out


def norm_services(run_dir, cfg):
    """One record per (host, port, protocol) — nmap-enriched, else masscan-basic."""
    mass, nm = parse_masscan(run_dir), parse_nmap_xml(run_dir)
    for key in sorted(set(mass) | set(nm)):
        ip, port, proto = key
        e = nm.get(key) or mass[key]
        rec = envelope(cfg, e["source_tool"], ip=ip)
        rec.update({
            "port": port,
            "protocol": proto,
            "state": e.get("state", "open"),
            "service": e.get("service"),
            "product": e.get("product"),
            "version": e.get("version"),
            "extra_info": e.get("extra_info"),
            "banner": None,        # SHOW does not run --script banner
            "cpe": e.get("cpe", []),
        })
        yield rec


# ── hosts (union of masscan-alive + arp + nbt + nmap-OS, incl. port-less) ────
def parse_alive(run_dir):
    p = os.path.join(run_dir, "hosts_alive.txt")
    if not os.path.exists(p):
        return set()
    with open(p) as fh:
        return {ln.strip() for ln in fh if ln.strip()}


def parse_tsv_map(run_dir, name):
    """ip -> value from a two-column `ip\\tvalue` TSV (arp.tsv / nbt.tsv)."""
    out = {}
    p = os.path.join(run_dir, name)
    if not os.path.exists(p):
        return out
    with open(p) as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[0]:
                out[parts[0]] = parts[1] or None
    return out


def parse_nmap_os(run_dir):
    """ip -> {os_name, os_accuracy} from nmap.xml + nmap6.xml (-O osmatch, best guess)."""
    out = {}
    for fn in ("nmap.xml", "nmap6.xml"):
        p = os.path.join(run_dir, fn)
        if not os.path.exists(p):
            continue
        try:
            root = ET.parse(p).getroot()
        except ET.ParseError:
            PARSE_ERRORS.add(fn.split(".")[0])   # nmap.xml → nmap, nmap6.xml → nmap6: corrupt XML degrades the run
            continue
        for host in root.findall("host"):
            ip = next((a.get("addr") for a in host.findall("address")
                       if a.get("addrtype") in ("ipv4", "ipv6")), None)
            osel = host.find("os")
            m = osel.find("osmatch") if osel is not None else None
            if not ip or m is None:
                continue
            try:
                acc = int(m.get("accuracy"))
            except (TypeError, ValueError):
                acc = None
            out[ip] = {"os_name": m.get("name"), "os_accuracy": acc}
    return out


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def norm_hosts(run_dir, cfg):
    """One record per live host — including port-less arp/nbt-only hosts."""
    alive = parse_alive(run_dir)
    arp = parse_tsv_map(run_dir, "arp.tsv")
    nbt = parse_tsv_map(run_dir, "nbt.tsv")
    osd = parse_nmap_os(run_dir)
    for ip in sorted(alive | set(arp) | set(nbt) | set(osd)):
        tool = ("masscan" if ip in alive else "arp-scan" if ip in arp
                else "nbtscan" if ip in nbt else "nmap")
        o = osd.get(ip, {})
        rec = envelope(cfg, tool, ip=ip)
        rec.update({
            "is_private": is_private_ip(ip),
            "ptr_record": None,          # TODO: bounded reverse-DNS enrichment
            "asn": None, "asn_org": None, "country_code": None,
            "mac": arp.get(ip),
            "netbios": nbt.get(ip),
            "os_name": o.get("os_name"),
            "os_accuracy": o.get("os_accuracy"),
        })
        yield rec


# ── tls (from testssl.json cert fields) ──────────────────────────────────────
# testssl --jsonfile is a flat array of {id, ip, port, severity, finding}. The
# cert facts are spread across entries keyed by `id`; we group by (ip, port) and
# pull them out. ⚠ testssl `id` names + date formats vary by version — confirm on
# first live run (decision #3). A group with no fingerprint is skipped (this
# stream exists for fingerprint_sha256, spec §4.4).
def load_testssl(run_dir):
    """testssl --jsonfile: flat array of {id, ip, port, severity, finding}."""
    p = os.path.join(run_dir, "testssl.json")
    if not os.path.exists(p):
        return []
    try:
        with open(p) as fh:
            data = json.load(fh)
    except json.JSONDecodeError:
        PARSE_ERRORS.add("testssl")
        return []
    except OSError:
        return []
    if isinstance(data, dict) and isinstance(data.get("scanResult"), list):
        data = data["scanResult"]
    if isinstance(data, list):
        # each row should be a testssl record (dict with an id). Flag degraded if ANY row isn't — including a
        # single junk entry in an otherwise-good array — while still returning the list so good rows parse.
        # (Empty list = testssl ran and found nothing → clean.)
        if any(not (isinstance(e, dict) and "id" in e) for e in data):
            PARSE_ERRORS.add("testssl")
        return data
    PARSE_ERRORS.add("testssl")   # valid JSON but not a recognized testssl shape → degrade, don't silently empty
    return []


def parse_testssl(run_dir):
    """Group testssl entries by (ip, port) -> {id: [entries]}."""
    groups = {}
    for e in load_testssl(run_dir):
        if not isinstance(e, dict):
            continue
        ipf = e.get("ip") or e.get("fqdn") or ""
        ip = ipf.split("/")[-1] if ipf else ""
        try:
            port = int(e.get("port"))
        except (TypeError, ValueError):
            continue
        groups.setdefault((ip, port), {}).setdefault(e.get("id", ""), []).append(e)
    return groups


def first_finding(ids, *keys):
    for k in keys:
        if ids.get(k):
            return ids[k][0].get("finding")
    return None


def norm_tls(run_dir, cfg):
    for (ip, port), ids in sorted(parse_testssl(run_dir).items()):
        fp = first_finding(ids, "cert_fingerprintSHA256")
        if not fp:
            continue
        fp = fp.replace("SHA256", "").strip()
        sans_raw = first_finding(ids, "cert_subjectAltName", "cert_SAN")
        sans = [s for s in re.split(r"[\s,]+", sans_raw) if s] if sans_raw else []
        keysz = first_finding(ids, "cert_keySize", "cert_keysize")
        key_algo = key_bits = None
        if keysz:
            am = re.search(r"[A-Za-z]+", keysz)
            bm = re.search(r"\d+", keysz)
            key_algo = am.group(0) if am else None
            key_bits = int(bm.group(0)) if bm else None
        issues = [e.get("finding") or idk
                  for idk, entries in ids.items() if not idk.startswith("cert_")
                  for e in entries
                  if (e.get("severity") or "").upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL")]
        rec = envelope(cfg, "testssl", ip=ip)
        rec.update({
            "port": port,
            "fingerprint_sha256": fp,
            "subject_cn": first_finding(ids, "cert_commonName", "cert_CN"),
            "subject_sans": sans,
            "issuer": first_finding(ids, "cert_caIssuers", "cert_issuer", "cert_issuerDN"),
            "not_before": first_finding(ids, "cert_notBefore"),
            "not_after": first_finding(ids, "cert_notAfter"),
            "serial_number": first_finding(ids, "cert_serialNumber", "cert_serial"),
            "key_algorithm": key_algo,
            "key_bits": key_bits,
            "signature_algorithm": first_finding(ids, "cert_signatureAlgorithm", "cert_signatureAlgo"),
            "grade": first_finding(ids, "overall_grade", "rating", "grade"),
            "issues": issues,
        })
        yield rec


# ── findings (unified: nuclei + testssl → one shape) ────────────────────────
def _first(v):
    return (v[0] if v else None) if isinstance(v, list) else v


def _list(v):
    return v if isinstance(v, list) else [] if v is None else [v]


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _split_first(v):
    if not v:
        return None
    return _first(v) if isinstance(v, list) else v.split()[0]


def severity_norm(s):
    s = (s or "").strip().lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    return {"informational": "info", "information": "info", "none": "info", "log": "info",
            "debug": "info", "warn": "low", "warning": "low", "ok": "info"}.get(s, "info")


def nuclei_category(cve, tags, tid, sev):
    hay = (" ".join(tags) + " " + (tid or "")).lower()
    if cve:
        return "vulnerability"
    if "misconfig" in hay:
        return "misconfiguration"
    if "exposure" in hay or "exposed" in hay or "disclosure" in hay:
        return "exposure"
    if sev == "info":
        return "information"
    return "vulnerability"


def nuclei_findings(run_dir, cfg):
    for n in read_jsonl(os.path.join(run_dir, "nuclei.jsonl")):
        info = n.get("info") or {}
        cls = info.get("classification") or {}
        url = n.get("url") or n.get("matched-at")
        tid = n.get("template-id") or n.get("templateID") or n.get("template") or ""
        cve = _split_first(cls.get("cve-id") or cls.get("cve_id"))
        sev = severity_norm(n.get("severity") or info.get("severity"))
        rec = envelope(cfg, "nuclei", ip=n.get("ip"))
        rec.update({
            "url": url, "port": port_from_url(url),
            "category": nuclei_category(cve, info.get("tags") or [], tid, sev),
            "template_id": tid or None, "cve_id": cve,
            "cwe_id": _split_first(cls.get("cwe-id") or cls.get("cwe_id")),
            "title": info.get("name") or tid or "finding",
            "description": info.get("description"), "severity": sev,
            "cvss_score": _num(cls.get("cvss-score") or cls.get("cvss_score")),
            "cvss_vector": cls.get("cvss-metrics") or cls.get("cvss_metrics"),
            "matched_at": n.get("matched-at") or url,
            "evidence": n.get("matcher-name") or n.get("matcher-status"),
            "references": _list(info.get("reference")),
            "remediation": info.get("remediation"), "raw": n,
        })
        yield rec


def testssl_findings(run_dir, cfg):
    for e in load_testssl(run_dir):
        if not isinstance(e, dict):
            continue
        sev = severity_norm(e.get("severity"))
        if sev not in ("low", "medium", "high", "critical"):
            continue
        ipf = e.get("ip") or e.get("fqdn") or ""
        ip = ipf.split("/")[-1] if ipf else None
        try:
            port = int(e.get("port"))
        except (TypeError, ValueError):
            port = None
        rec = envelope(cfg, "testssl", ip=ip)
        rec.update({
            "url": None, "port": port, "category": "weak_tls",
            "template_id": e.get("id") or None,
            "cve_id": _split_first(e.get("cve")), "cwe_id": _split_first(e.get("cwe")),
            "title": e.get("id") or "tls-finding", "description": e.get("finding"),
            "severity": sev, "cvss_score": None, "cvss_vector": None,
            "matched_at": (
                (f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}") if ip and port else ip
            ),  # bracket IPv6 so host/port stay splittable downstream (2001:db8::1:443 is ambiguous)
            "evidence": e.get("finding"), "references": [],
            "remediation": None, "raw": e,
        })
        yield rec


def norm_findings(run_dir, cfg):
    yield from nuclei_findings(run_dir, cfg)
    yield from testssl_findings(run_dir, cfg)


# ── entrypoint ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="SHOW sensor-output/1.0 normalizer")
    ap.add_argument("--run-dir", required=True)
    ap.add_argument("--scan-id", required=True, help="ISO-8601 UTC, stamped on every record")
    ap.add_argument("--observed-at", required=True, help="ISO-8601 UTC")
    a = ap.parse_args()
    cfg = {"scan_id": a.scan_id, "observed_at": a.observed_at,
           "host_ctx": load_host_context(a.run_dir)}

    # Clear any stale degraded marker from a prior normalize of this run dir, so a now-clean re-run
    # (e.g. after fixing/replacing a corrupt tool file) is not perpetually reported as degraded.
    sidecar = os.path.join(a.run_dir, ".normalize_degraded")
    if os.path.exists(sidecar):
        os.remove(sidecar)

    # Streams the normalizer owns today. 6c services · 6d hosts · 6e tls · 6g
    # findings wire in at their stages; until then merge() emits those.
    n = write_stream(a.run_dir, "web_assets.ndjson", norm_web_assets(a.run_dir, cfg), cfg)
    print(f"[normalize] web_assets.ndjson: {n} record(s)")
    n = write_stream(a.run_dir, "services.ndjson", norm_services(a.run_dir, cfg), cfg)
    print(f"[normalize] services.ndjson: {n} record(s)")
    n = write_stream(a.run_dir, "hosts.ndjson", norm_hosts(a.run_dir, cfg), cfg)
    print(f"[normalize] hosts.ndjson: {n} record(s)")
    # tls is emit-when-tool-ran (spec §1 ○): omit the file entirely if testssl didn't run.
    if os.path.exists(os.path.join(a.run_dir, "testssl.json")):
        n = write_stream(a.run_dir, "tls.ndjson", norm_tls(a.run_dir, cfg), cfg)
        print(f"[normalize] tls.ndjson: {n} record(s)")
    n = write_stream(a.run_dir, "findings.ndjson", norm_findings(a.run_dir, cfg), cfg)
    print(f"[normalize] findings.ndjson: {n} record(s)")

    # Malformed tool output (JSON or nmap XML) isn't fatal (we still emit what parsed), but it must not read
    # as a clean run: drop a sidecar the manifest folds into degraded_tools so status becomes "degraded".
    if PARSE_ERRORS:
        with open(sidecar, "w") as fh:
            fh.write("\n".join(sorted(PARSE_ERRORS)) + "\n")
        for t in sorted(PARSE_ERRORS):
            print(f"[normalize] WARNING: unparseable output from {t} — records skipped; run marked degraded")


if __name__ == "__main__":
    main()
