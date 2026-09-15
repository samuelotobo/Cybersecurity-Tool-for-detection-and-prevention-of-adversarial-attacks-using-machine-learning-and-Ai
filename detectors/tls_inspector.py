"""
Deep Packet Inspection — TLS/SSL Metadata Analyser.

Inspects TLS Client Hello packets without decrypting traffic.
Extracts SNI (Server Name Indication), TLS version, cipher suites,
and computes JA3 fingerprints to identify malware / unusual clients.

JA3 method: https://github.com/salesforce/ja3
No decryption — only handshake metadata is analysed.
"""

import hashlib
import struct
import threading
from collections import defaultdict
from datetime import datetime
from typing import Callable


# Known malicious / suspicious JA3 hashes (sample — extend as needed)
_KNOWN_BAD_JA3: dict[str, str] = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike Beacon",
    "6734f37431109a4e49b3f9e46b52b749": "Metasploit Handler",
    "b386946a5a44d1ddcc843bc75336dfce": "Dridex Banking Trojan",
    "a0e9f5d64349fb13191bc781f81f42e1": "Emotet Loader",
    "c12f54a3f91dc7bafd92cb59fe009a35": "TrickBot C2",
    "d4b4e8e9d8f7c3f5d1d2e9f8b3c4a5b6": "AsyncRAT",
    "72a589da586844d7f0818ce684948eea": "Mirai Botnet",
    "3b5074b1b5d032e5620f69f9f700ff0e": "Lazarus Group TLS",
}

# Cipher suite IDs that indicate weak/deprecated crypto
_WEAK_CIPHERS: set[int] = {
    0x0004, 0x0005,   # RC4
    0x000A,           # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x002F, 0x0035,   # AES-CBC (no forward secrecy)
    0xFF85, 0x00FF,   # GREASE values / unknown
}

# TLS record and handshake type constants
_TLS_RECORD_TYPE_HANDSHAKE  = 22
_TLS_HANDSHAKE_CLIENT_HELLO = 1


class TLSInspector:
    """
    Sniffs TCP packets on common TLS ports (443, 8443, etc.) and
    parses TLS Client Hello messages from the raw payload.

    Call process_packet(pkt) from a Scapy sniffer callback.
    """

    _TLS_PORTS = {443, 8443, 4443, 9443, 8080, 465, 587, 993, 995}

    def __init__(self, on_alert: Callable[[dict], None] | None = None):
        self._on_alert = on_alert or (lambda _: None)
        self._lock     = threading.Lock()
        # track SNI → {src_ips} for detecting one host hitting many destinations
        self._sni_map: dict[str, set[str]] = defaultdict(set)
        self._ja3_seen: dict[str, int] = defaultdict(int)

    def process_packet(self, pkt) -> None:
        try:
            from scapy.layers.inet import IP, TCP
        except ImportError:
            return

        if not pkt.haslayer(TCP):
            return
        tcp = pkt.getlayer(TCP)
        if tcp.dport not in self._TLS_PORTS and tcp.sport not in self._TLS_PORTS:
            return

        payload = bytes(tcp.payload)
        if len(payload) < 6:
            return

        result = _parse_client_hello(payload)
        if result is None:
            return

        sni, tls_ver, ciphers, extensions, ec_curves, ec_formats = result
        src_ip = pkt.getlayer(IP).src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt.getlayer(IP).dst if pkt.haslayer(IP) else "unknown"

        ja3_str = _build_ja3_string(tls_ver, ciphers, extensions, ec_curves, ec_formats)
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Check against known malicious JA3 hashes
        if ja3_hash in _KNOWN_BAD_JA3:
            malware = _KNOWN_BAD_JA3[ja3_hash]
            self._on_alert({
                "rule_name": f"Malicious TLS — {malware}",
                "severity":  "critical",
                "source_ip": src_ip,
                "message":   (
                    f"JA3 fingerprint matches {malware} C2 traffic. "
                    f"JA3={ja3_hash}, SNI={sni or 'none'}, dst={dst_ip}"
                ),
                "timestamp": ts,
                "category":  "tls",
                "ja3":       ja3_hash,
                "sni":       sni,
            })

        # Check for weak cipher suites
        weak = [c for c in ciphers if c in _WEAK_CIPHERS]
        if weak:
            self._on_alert({
                "rule_name": "Weak TLS Ciphers",
                "severity":  "medium",
                "source_ip": src_ip,
                "message":   (
                    f"TLS Client Hello from {src_ip} advertises "
                    f"{len(weak)} deprecated cipher(s): "
                    + ", ".join(f"0x{c:04X}" for c in weak[:4])
                    + (f" +{len(weak)-4} more" if len(weak) > 4 else "")
                    + f". SNI={sni or 'none'}"
                ),
                "timestamp": ts,
                "category":  "tls",
                "ja3":       ja3_hash,
            })

        # Check for missing SNI (raw IP connection — suspicious for HTTPS)
        if tcp.dport == 443 and not sni:
            self._on_alert({
                "rule_name": "TLS without SNI",
                "severity":  "low",
                "source_ip": src_ip,
                "message":   (
                    f"HTTPS connection from {src_ip} to {dst_ip}:443 "
                    f"sent no SNI — possible direct IP C2 channel. JA3={ja3_hash}"
                ),
                "timestamp": ts,
                "category":  "tls",
                "ja3":       ja3_hash,
            })

        # Track JA3 uniqueness — same fingerprint connecting to many destinations is suspicious
        with self._lock:
            if sni:
                self._sni_map[ja3_hash].add(dst_ip)
            count = len(self._sni_map.get(ja3_hash, set()))
        if count == 15:
            self._on_alert({
                "rule_name": "TLS Fingerprint Scanning",
                "severity":  "high",
                "source_ip": src_ip,
                "message":   (
                    f"Single TLS fingerprint (JA3={ja3_hash}) contacted "
                    f"{count} distinct destinations — possible botnet scan or RAT beacon."
                ),
                "timestamp": ts,
                "category":  "tls",
                "ja3":       ja3_hash,
            })


# ── TLS Client Hello parser ─────────────────────────────────────────────────

def _parse_client_hello(
    data: bytes,
) -> tuple[str, int, list[int], list[int], list[int], list[int]] | None:
    """
    Parse a raw TCP payload looking for a TLS Client Hello.
    Returns (sni, tls_version, ciphers, ext_types, ec_curves, ec_formats)
    or None if the packet is not a Client Hello.
    """
    try:
        if data[0] != _TLS_RECORD_TYPE_HANDSHAKE:
            return None
        # TLS record header: type(1) + version(2) + length(2)
        if len(data) < 5:
            return None
        rec_length = struct.unpack("!H", data[3:5])[0]
        if len(data) < 5 + rec_length:
            return None

        handshake = data[5:5 + rec_length]
        if not handshake or handshake[0] != _TLS_HANDSHAKE_CLIENT_HELLO:
            return None

        # Handshake header: type(1) + length(3) + client_hello body
        if len(handshake) < 4:
            return None
        pos  = 4   # skip type + 3-byte length
        body = handshake

        # client version (2 bytes)
        if pos + 2 > len(body):
            return None
        tls_version = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2

        # random (32 bytes)
        pos += 32

        # session_id length (1 byte) + session_id
        if pos + 1 > len(body):
            return None
        sid_len = body[pos]
        pos += 1 + sid_len

        # cipher suites length (2 bytes) + cipher suites
        if pos + 2 > len(body):
            return None
        cs_len  = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if pos + 2 <= len(body):
                c = struct.unpack("!H", body[pos:pos + 2])[0]
                # Skip GREASE values (0xXaXa pattern)
                if not _is_grease(c):
                    ciphers.append(c)
            pos += 2

        # compression methods length + methods
        if pos + 1 > len(body):
            return None
        comp_len = body[pos]
        pos += 1 + comp_len

        # extensions
        sni        = ""
        ext_types  = []
        ec_curves  = []
        ec_formats = []

        if pos + 2 > len(body):
            return (sni, tls_version, ciphers, ext_types, ec_curves, ec_formats)

        ext_total = struct.unpack("!H", body[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_total

        while pos + 4 <= ext_end and pos + 4 <= len(body):
            ext_type   = struct.unpack("!H", body[pos:pos + 2])[0]
            ext_length = struct.unpack("!H", body[pos + 2:pos + 4])[0]
            pos += 4
            ext_data = body[pos:pos + ext_length]
            pos += ext_length

            if not _is_grease(ext_type):
                ext_types.append(ext_type)

            # SNI extension (type 0)
            if ext_type == 0 and len(ext_data) > 5:
                # server_name_list_length(2) + name_type(1) + name_length(2) + name
                try:
                    name_type = ext_data[2]
                    if name_type == 0:   # host_name
                        name_len = struct.unpack("!H", ext_data[3:5])[0]
                        sni = ext_data[5:5 + name_len].decode("utf-8", errors="ignore")
                except Exception:
                    pass

            # Supported groups / elliptic curves (type 10)
            elif ext_type == 10 and len(ext_data) >= 2:
                curves_len = struct.unpack("!H", ext_data[:2])[0]
                for i in range(0, curves_len, 2):
                    if 2 + i + 2 <= len(ext_data):
                        c = struct.unpack("!H", ext_data[2 + i:2 + i + 2])[0]
                        if not _is_grease(c):
                            ec_curves.append(c)

            # EC point formats (type 11)
            elif ext_type == 11 and len(ext_data) >= 1:
                fmts_len = ext_data[0]
                ec_formats = list(ext_data[1:1 + fmts_len])

        return (sni, tls_version, ciphers, ext_types, ec_curves, ec_formats)

    except Exception:
        return None


def _build_ja3_string(
    tls_ver: int,
    ciphers: list[int],
    extensions: list[int],
    ec_curves: list[int],
    ec_formats: list[int],
) -> str:
    parts = [
        str(tls_ver),
        "-".join(str(c) for c in ciphers),
        "-".join(str(e) for e in extensions),
        "-".join(str(c) for c in ec_curves),
        "-".join(str(f) for f in ec_formats),
    ]
    return ",".join(parts)


def _is_grease(value: int) -> bool:
    """GREASE values follow the 0x?a?a pattern (RFC 8701)."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)
