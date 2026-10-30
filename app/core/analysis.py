"""Turn a PCAP/PCAPNG file into a JSON-serialisable summary using Scapy.

Each packet is counted once in the protocol breakdown, under its most specific
category: ARP, DNS, HTTP, TLS, ICMP, then plain TCP/UDP, else "other".
"""

import io
from collections import Counter, defaultdict

from django.conf import settings
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader

PROTOCOLS = ["TCP", "UDP", "ICMP", "ARP", "DNS", "HTTP", "TLS", "other"]

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")
TLS_CONTENT_TYPES = (0x14, 0x15, 0x16, 0x17)
MAX_DNS_NAMES = 50
TOP_N = 10


def _is_http(payload):
    return payload.startswith(HTTP_METHODS) or payload.startswith(b"HTTP/1.")


def _is_tls(payload):
    return len(payload) >= 5 and payload[0] in TLS_CONTENT_TYPES and payload[1] == 0x03


def _classify(pkt, payload):
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(DNS):
        return "DNS"
    if pkt.haslayer(TCP):
        if payload and _is_http(payload):
            return "HTTP"
        if payload and _is_tls(payload):
            return "TLS"
        return "TCP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    if pkt.haslayer(UDP):
        return "UDP"
    return "other"


def _ip_pair(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src, pkt[IP].dst
    if pkt.haslayer(IPv6):
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None


class _Findings:
    """Collect cleartext-credential findings without keeping any secret values."""

    def __init__(self):
        self._items = {}

    def add(self, kind, client, server, **extra):
        key = (kind, client, server)
        if key not in self._items:
            self._items[key] = {"type": kind, "client": client, "server": server, "packets": 0, **extra}
        item = self._items[key]
        item["packets"] += 1
        for name, value in extra.items():
            if value and not item.get(name):
                item[name] = value

    def as_list(self):
        return list(self._items.values())


def _check_cleartext(findings, src, dst, sport, dport, payload):
    if 21 in (sport, dport) and payload:
        client, server = (src, dst) if dport == 21 else (dst, src)
        for line in payload.split(b"\r\n"):
            upper = line[:5].upper()
            if upper == b"USER ":
                username = line[5:].decode("utf-8", "replace").strip()[:100]
                findings.add("ftp_credentials", client, server, username=username, password_seen=False,
                             description="FTP login sent in cleartext")
            elif upper == b"PASS ":
                # Record only that a password was sent; the value itself is never kept.
                findings.add("ftp_credentials", client, server, password_seen=True,
                             description="FTP login sent in cleartext")
    if 23 in (sport, dport):
        client, server = (src, dst) if dport == 23 else (dst, src)
        findings.add("telnet", client, server, description="Telnet session (cleartext remote shell)")
    if payload and b"authorization: basic " in payload.lower() and _is_http(payload):
        host = ""
        for line in payload.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host = line[5:].decode("utf-8", "replace").strip()[:200]
                break
        findings.add("http_basic_auth", src, dst, host=host,
                     description="HTTP Basic Authorization header sent in cleartext")


def analyse_pcap_bytes(data):
    """Parse capture bytes and return the summary dict. Raises on unreadable input."""
    max_packets = settings.MAX_ANALYSED_PACKETS
    protocols = Counter({name: 0 for name in PROTOCOLS})
    sources = Counter()
    conversations = defaultdict(lambda: {"packets": 0, "bytes": 0})
    dns_names = []
    seen_dns = set()
    findings = _Findings()
    first_ts = last_ts = None
    packet_count = 0
    total_bytes = 0
    truncated = False

    reader = PcapReader(io.BytesIO(data))
    try:
        for pkt in reader:
            if packet_count >= max_packets:
                truncated = True
                break
            packet_count += 1
            size = len(pkt)
            total_bytes += size

            ts = float(pkt.time)
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

            payload = b""
            sport = dport = None
            if pkt.haslayer(TCP):
                payload = bytes(pkt[TCP].payload)
                sport, dport = pkt[TCP].sport, pkt[TCP].dport
            elif pkt.haslayer(UDP):
                sport, dport = pkt[UDP].sport, pkt[UDP].dport

            protocols[_classify(pkt, payload)] += 1

            src, dst = _ip_pair(pkt)
            if src:
                sources[src] += 1
                a, b = sorted((src, dst))
                conv = conversations[(a, b)]
                conv["packets"] += 1
                conv["bytes"] += size
                if pkt.haslayer(TCP):
                    _check_cleartext(findings, src, dst, sport, dport, payload)

            if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0 and len(dns_names) < MAX_DNS_NAMES:
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", "replace")
                qname = qname.rstrip(".")
                if qname and qname not in seen_dns:
                    seen_dns.add(qname)
                    dns_names.append(qname)
    finally:
        reader.close()

    top_conversations = sorted(conversations.items(), key=lambda item: item[1]["packets"], reverse=True)[:TOP_N]
    return {
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "duration_seconds": round((last_ts - first_ts), 3) if packet_count else 0.0,
        "truncated": truncated,
        "protocols": {name: protocols[name] for name in PROTOCOLS},
        "top_sources": [{"ip": ip, "packets": count} for ip, count in sources.most_common(TOP_N)],
        "top_conversations": [
            {"a": a, "b": b, "packets": stats["packets"], "bytes": stats["bytes"]}
            for (a, b), stats in top_conversations
        ],
        "dns_queries": dns_names,
        "cleartext_findings": findings.as_list(),
    }
