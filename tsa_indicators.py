"""Indicators of compromise: distrusted certificates matched by SHA-256 of the
certificate and by SHA-256 of its SubjectPublicKeyInfo (catches re-issued or
cross-signed certificates that reuse a compromised key).

Includes a minimal DER walker so SPKI extraction needs only the standard library.
"""
from __future__ import annotations

import hashlib
import json
import re
import ssl
from pathlib import Path

PEM_RE = re.compile(r"-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----\n?", re.S)
SPKI_PREFIX = "SPKI:"
PEM_LINE_SAMPLES = (3, 6)  # base64 lines of each PEM searched for in binaries
MIN_PEM_LINES = 8
DER_PREFIX_BYTES = 120  # start of the certificate DER (version, serial, issuer): the cert itself
# Patched verifiers (rustls-webpki 0.103.16, Go 1.27.3) embed the compromised
# intermediates' keys to *reject* them; a key without its certificate is a blocklist.
BLOCKLIST_MARK = " [key only: distrust blocklist]"


# ------------------------------------------------------------------------- DER
def read_tlv(buf: bytes, off: int) -> tuple[int, int, int] | None:
    """Return (tag, content_start, content_end) of the TLV at off, or None."""
    if off + 2 > len(buf):
        return None
    tag = buf[off]
    length = buf[off + 1]
    pos = off + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            return None
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    if pos + length > len(buf):
        return None
    return tag, pos, pos + length


def spki_der(cert_der: bytes) -> bytes | None:
    """Full SubjectPublicKeyInfo TLV from a DER certificate."""
    cert = read_tlv(cert_der, 0)
    if not cert:
        return None
    tbs = read_tlv(cert_der, cert[1])
    if not tbs or tbs[0] != 0x30:
        return None
    off = tbs[1]
    first = read_tlv(cert_der, off)
    if not first:
        return None
    if first[0] == 0xA0:  # explicit version
        off = first[2]
    # serial, signature algorithm, issuer, validity, subject, then SPKI
    for _ in range(5):
        field = read_tlv(cert_der, off)
        if not field:
            return None
        off = field[2]
    spki = read_tlv(cert_der, off)
    if not spki or spki[0] != 0x30:
        return None
    return cert_der[off:spki[2]]


def spki_content(spki: bytes) -> bytes:
    """SPKI without its outer SEQUENCE header (the form webpki-roots embeds)."""
    tlv = read_tlv(spki, 0)
    return spki[tlv[1]:tlv[2]] if tlv else spki


def cert_keys(der: bytes) -> list[str]:
    """Lookup keys for one certificate: its SHA-256, then its SPKI SHA-256."""
    keys = [hashlib.sha256(der).hexdigest().upper()]
    spki = spki_der(der)
    if spki:
        keys.append(SPKI_PREFIX + hashlib.sha256(spki).hexdigest().upper())
    return keys


def pem_blocks_re() -> re.Pattern:
    return PEM_RE


def der_from_pem(block: str) -> bytes | None:
    try:
        return ssl.PEM_cert_to_DER_cert(block.strip())
    except ValueError:
        return None


# ------------------------------------------------------------------ indicators
def load_preset_json(path: str) -> tuple[dict[str, str], list[dict]]:
    """Return (lookup, entries). lookup maps cert and SPKI keys to a label."""
    entries = json.loads(Path(path).read_text())["certificates"]
    lookup: dict[str, str] = {}
    for e in entries:
        label = f"{e['name']} ({e['kind']})"
        lookup[e["sha256"]] = label
        lookup[SPKI_PREFIX + e["spki_sha256"]] = f"{label} [same key]"
    return lookup, entries


def first_match(keys: list[str], lookup: dict[str, str]) -> str | None:
    for k in keys:
        if k in lookup:
            return k
    return None


def binary_patterns(entries: list[dict]) -> list[tuple[bytes, str]]:
    """Byte patterns that reveal a certificate or key embedded in a binary:
    the certificate DER itself, the SPKI body (webpki-roots trust anchors for
    roots; distrust blocklists for intermediates) and sample PEM lines (PEM
    strings compiled into Node, Electron and similar)."""
    patterns: list[tuple[bytes, str]] = []
    for e in entries:
        der = der_from_pem(e["pem"])
        if not der:
            continue
        label = f"{e['name']} ({e['kind']})"
        patterns.append((der[:DER_PREFIX_BYTES], label))
        spki = spki_der(der)
        if spki:
            # Trust stores carry roots as anchors (key + subject); an intermediate's
            # key alone is what blocklists embed.
            key_label = label if e["kind"] == "root" else label + BLOCKLIST_MARK
            patterns.append((spki_content(spki), key_label))
        lines = [ln for ln in e["pem"].splitlines() if not ln.startswith("-----")]
        if len(lines) < MIN_PEM_LINES:
            continue
        for i in PEM_LINE_SAMPLES:
            patterns.append((lines[i].encode(), label))
    return patterns


def trusted_labels(labels: list[str]) -> list[str]:
    """Drop blocklist-only hits: an intermediate whose certificate was also found
    stays; a key found without its certificate is the fix, not the problem."""
    full = {lb for lb in labels if not lb.endswith(BLOCKLIST_MARK)}
    return sorted(full)


def valid_hex(text: str) -> bool:
    return bool(re.fullmatch(r"[0-9A-F]{64}", text))
