"""Deployed sites: the chain a host actually serves, and Certificate
Transparency (crt.sh) for any certificate ever issued by an affected CA."""
from __future__ import annotations

import json
import socket
import ssl
import subprocess
import urllib.parse
import urllib.request

import tsa_indicators as ind

CONNECT_TIMEOUT = 15
CT_TIMEOUT = 60
CT_URL = "https://crt.sh/?q={q}&output=json&exclude=expired"
CERTSPOTTER_URL = ("https://api.certspotter.com/v1/issuances?domain={d}"
                   "&include_subdomains=true&expand=issuer&expand=dns_names")
AFFECTED_ISSUER_MARKERS = ("O=eMudhra", "emSign")


def split_host(site: str) -> tuple[str, int]:
    site = site.strip()
    if "://" in site:
        site = urllib.parse.urlparse(site).netloc
    host, _, port = site.partition(":")
    return host, int(port) if port else 443


def served_chain(host: str, port: int) -> list[bytes] | str:
    """DER certificates exactly as served (unverified on purpose), or an error."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=host) as tls:
                if hasattr(tls, "get_unverified_chain"):
                    return [c for c in tls.get_unverified_chain() if isinstance(c, bytes)]
                return openssl_chain(host, port)
    except (OSError, ssl.SSLError) as exc:
        return f"connect failed ({type(exc).__name__})"


def openssl_chain(host: str, port: int) -> list[bytes] | str:
    try:
        r = subprocess.run(["openssl", "s_client", "-showcerts", "-servername", host,
                            "-connect", f"{host}:{port}"], input="", capture_output=True,
                           text=True, timeout=CONNECT_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return "openssl s_client failed"
    ders = [ind.der_from_pem(b) for b in ind.PEM_RE.findall(r.stdout)]
    return [d for d in ders if d]


def audit_site(site: str, lookup: dict[str, str]) -> dict:
    host, port = split_host(site)
    chain = served_chain(host, port)
    base = {"store": f"site {host}", "kind": "site", "location": f"{host}:{port}", "version": ""}
    if isinstance(chain, str):
        return {**base, "status": "skipped", "total": "-", "found": [], "note": chain}
    found = []
    for der in chain:
        hit = ind.first_match(ind.cert_keys(der), lookup)
        if hit:
            found.append({"sha256": hit, "label": lookup[hit]})
    return {**base, "status": "PRESENT" if found else "absent", "total": len(chain),
            "found": found, "note": "served chain" + ("; re-issue with another CA now" if found else "")}


def audit_ct(domain: str) -> dict:
    """Unexpired certificates for domain and its subdomains issued under eMudhra."""
    host, _ = split_host(domain)
    url = CT_URL.format(q=urllib.parse.quote(f"%.{host}"))
    base = {"store": f"ct {host}", "kind": "ct", "location": "crt.sh", "version": ""}
    try:
        with urllib.request.urlopen(url, timeout=CT_TIMEOUT) as resp:
            rows = json.loads(resp.read() or b"[]")
    except (OSError, ValueError):
        return audit_certspotter(host)
    hits = [r for r in rows if any(m in r.get("issuer_name", "") for m in AFFECTED_ISSUER_MARKERS)]
    found = [{"sha256": f"crt.sh id {r['id']}", "label": f"{r.get('common_name')} by {r['issuer_name']}"}
             for r in hits]
    return {**base, "status": "PRESENT" if found else "absent", "total": len(rows), "found": found,
            "note": "unexpired certificates in CT logs"}


def audit_certspotter(host: str) -> dict:
    """Fallback CT search (SSLMate Cert Spotter; unexpired issuances only)."""
    base = {"store": f"ct {host}", "kind": "ct", "location": "certspotter", "version": ""}
    try:
        with urllib.request.urlopen(CERTSPOTTER_URL.format(d=urllib.parse.quote(host)),
                                    timeout=CT_TIMEOUT) as resp:
            rows = json.loads(resp.read() or b"[]")
    except (OSError, ValueError) as exc:
        return {**base, "status": "skipped", "total": "-", "found": [],
                "note": f"crt.sh and Cert Spotter unavailable ({type(exc).__name__}); retry later"}
    if not isinstance(rows, list):
        return {**base, "status": "skipped", "total": "-", "found": [], "note": "unexpected Cert Spotter reply"}
    hits = [r for r in rows
            if any(m.lower() in json.dumps(r.get("issuer", {})).lower() for m in ("emudhra", "emsign"))]
    found = [{"sha256": f"certspotter id {r.get('id')}",
              "label": f"{', '.join(r.get('dns_names', [])[:3])} by {r['issuer'].get('friendly_name')}"}
             for r in hits]
    issuers = sorted({(r.get("issuer") or {}).get("friendly_name", "?") for r in rows})
    return {**base, "status": "PRESENT" if found else "absent", "total": len(rows), "found": found,
            "note": "unexpired certificates in CT logs; issuers: " + ", ".join(issuers)}
