"""Generate synthetic PCAP files in memory with Scapy.

All traffic is invented: private / documentation IP ranges (RFC 1918, RFC 5737),
fictional .example domains and obviously fake credentials. Never real traffic.
"""

import base64
import io
import random

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

FAKE_FTP_USER = "demo_user"
FAKE_FTP_PASSWORD = "not-a-real-password"

DOMAINS = [
    "intranet.atlas-logistics.example",
    "tracking.atlas-logistics.example",
    "portal.medina-clinic.example",
    "records.medina-clinic.example",
    "loans.orion-microfinance.example",
    "api.orion-microfinance.example",
    "updates.vendor-software.example",
    "cdn.static-assets.example",
    "mail.packetnest-demo.example",
    "time.ntp-pool.example",
]

CLIENTS = ["10.0.10.11", "10.0.10.12", "10.0.10.25", "10.0.20.7", "10.0.20.31"]
DNS_SERVER = "10.0.0.53"
WEB_SERVERS = ["192.0.2.10", "192.0.2.80", "198.51.100.20"]
TLS_SERVERS = ["203.0.113.5", "203.0.113.44"]
FTP_SERVER = "198.51.100.21"
TELNET_SERVER = "10.0.30.2"
GATEWAY = "10.0.0.1"

KINDS = ["mixed", "dns", "web", "tls", "ftp", "icmp", "telnet", "basic_auth"]


class _Builder:
    def __init__(self, seed, start_time=1_760_000_000.0):
        self.rng = random.Random(seed)
        self.now = start_time + self.rng.randint(0, 86_400 * 30)
        self.packets = []

    def add(self, pkt, gap=None):
        self.now += gap if gap is not None else self.rng.uniform(0.0005, 0.05)
        pkt.time = self.now
        self.packets.append(pkt)

    def mac(self):
        return "02:00:%02x:%02x:%02x:%02x" % tuple(self.rng.randint(0, 255) for _ in range(4))

    def eth(self):
        return Ether(src=self.mac(), dst=self.mac())

    # --- building blocks -------------------------------------------------

    def tcp_session(self, client, server, dport, exchanges):
        """Handshake, then (direction, payload) exchanges, then FIN."""
        sport = self.rng.randint(40000, 65000)
        cseq = self.rng.randint(1, 2**31)
        sseq = self.rng.randint(1, 2**31)
        self.add(self.eth() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
        self.add(self.eth() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
        cseq += 1
        sseq += 1
        self.add(self.eth() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        for direction, payload in exchanges:
            if direction == "c":
                self.add(self.eth() / IP(src=client, dst=server)
                         / TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(payload))
                cseq += len(payload)
                self.add(self.eth() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="A", seq=sseq, ack=cseq))
            else:
                self.add(self.eth() / IP(src=server, dst=client)
                         / TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(payload))
                sseq += len(payload)
                self.add(self.eth() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        self.add(self.eth() / IP(src=client, dst=server) / TCP(sport=sport, dport=dport, flags="FA", seq=cseq, ack=sseq))
        self.add(self.eth() / IP(src=server, dst=client) / TCP(sport=dport, dport=sport, flags="FA", seq=sseq, ack=cseq + 1))

    def dns_lookups(self, count):
        for _ in range(count):
            client = self.rng.choice(CLIENTS)
            name = self.rng.choice(DOMAINS)
            qid = self.rng.randint(1, 65535)
            sport = self.rng.randint(1024, 65535)
            answer = "192.0.2.%d" % self.rng.randint(1, 254)
            self.add(self.eth() / IP(src=client, dst=DNS_SERVER) / UDP(sport=sport, dport=53)
                     / DNS(id=qid, rd=1, qd=DNSQR(qname=name)))
            self.add(self.eth() / IP(src=DNS_SERVER, dst=client) / UDP(sport=53, dport=sport)
                     / DNS(id=qid, qr=1, ra=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, ttl=300, rdata=answer)))

    def http_gets(self, count, basic_auth=False):
        paths = ["/", "/status", "/shipments?page=2", "/static/app.js", "/reports/weekly", "/api/health"]
        for _ in range(count):
            client = self.rng.choice(CLIENTS)
            server = self.rng.choice(WEB_SERVERS)
            host = self.rng.choice(DOMAINS)
            request = f"GET {self.rng.choice(paths)} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: PacketNestDemo/1.0\r\n"
            if basic_auth:
                token = base64.b64encode(f"{FAKE_FTP_USER}:{FAKE_FTP_PASSWORD}".encode()).decode()
                request += f"Authorization: Basic {token}\r\n"
            request += "Accept: */*\r\n\r\n"
            body = "<html><body>demo</body></html>"
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(body)}\r\n\r\n{body}"
            self.tcp_session(client, server, 80, [("c", request.encode()), ("s", response.encode())])

    def tls_flows(self, count):
        for _ in range(count):
            client = self.rng.choice(CLIENTS)
            server = self.rng.choice(TLS_SERVERS)

            def record(content_type, version, size):
                body = bytes(self.rng.getrandbits(8) for _ in range(size))
                return bytes([content_type]) + version + size.to_bytes(2, "big") + body

            client_hello = record(0x16, b"\x03\x01", 180)
            server_hello = record(0x16, b"\x03\x03", 90) + record(0x14, b"\x03\x03", 1)
            app_data = [record(0x17, b"\x03\x03", self.rng.randint(80, 600)) for _ in range(4)]
            exchanges = [("c", client_hello), ("s", server_hello)]
            for i, chunk in enumerate(app_data):
                exchanges.append(("c" if i % 2 == 0 else "s", chunk))
            self.tcp_session(client, server, 443, exchanges)

    def ftp_login(self):
        client = self.rng.choice(CLIENTS)
        self.tcp_session(client, FTP_SERVER, 21, [
            ("s", b"220 Demo FTP server ready\r\n"),
            ("c", f"USER {FAKE_FTP_USER}\r\n".encode()),
            ("s", b"331 Password required\r\n"),
            ("c", f"PASS {FAKE_FTP_PASSWORD}\r\n".encode()),
            ("s", b"230 Login successful\r\n"),
            ("c", b"PWD\r\n"),
            ("s", b'257 "/" is the current directory\r\n'),
            ("c", b"QUIT\r\n"),
            ("s", b"221 Goodbye\r\n"),
        ])

    def telnet_session(self):
        client = self.rng.choice(CLIENTS)
        self.tcp_session(client, TELNET_SERVER, 23, [
            ("s", b"\xff\xfd\x18\xff\xfd\x20"),
            ("s", b"switch-lab login: "),
            ("c", b"operator\r\n"),
            ("s", b"Password: "),
            ("c", b"********\r\n"),
            ("s", b"switch-lab> "),
            ("c", b"show interfaces\r\n"),
        ])

    def pings(self, count):
        for seq in range(count):
            client = self.rng.choice(CLIENTS)
            target = self.rng.choice([GATEWAY] + WEB_SERVERS)
            ident = self.rng.randint(1, 65535)
            self.add(self.eth() / IP(src=client, dst=target) / ICMP(type=8, id=ident, seq=seq) / Raw(b"x" * 32))
            self.add(self.eth() / IP(src=target, dst=client) / ICMP(type=0, id=ident, seq=seq) / Raw(b"x" * 32))

    def arps(self, count):
        for _ in range(count):
            client = self.rng.choice(CLIENTS)
            self.add(Ether(src=self.mac(), dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=client, pdst=GATEWAY))
            self.add(self.eth() / ARP(op=2, psrc=GATEWAY, pdst=client))

    def udp_noise(self, count):
        for _ in range(count):
            client = self.rng.choice(CLIENTS)
            self.add(self.eth() / IP(src=client, dst="10.0.0.123") / UDP(sport=self.rng.randint(1024, 65535), dport=123)
                     / Raw(bytes(48)))


def build_packets(kind="mixed", seed=0):
    if kind not in KINDS:
        raise ValueError(f"unknown synthetic capture kind: {kind}")
    b = _Builder(seed)
    if kind == "mixed":
        b.arps(2)
        b.dns_lookups(6)
        b.http_gets(3)
        b.tls_flows(2)
        b.ftp_login()
        b.pings(3)
        b.udp_noise(2)
    elif kind == "dns":
        b.dns_lookups(25)
        b.udp_noise(4)
    elif kind == "web":
        b.dns_lookups(5)
        b.http_gets(8)
    elif kind == "tls":
        b.dns_lookups(4)
        b.tls_flows(6)
    elif kind == "ftp":
        b.arps(1)
        b.ftp_login()
        b.dns_lookups(2)
    elif kind == "icmp":
        b.arps(3)
        b.pings(12)
    elif kind == "telnet":
        b.telnet_session()
        b.pings(2)
    elif kind == "basic_auth":
        b.dns_lookups(3)
        b.http_gets(2, basic_auth=True)
        b.http_gets(2)
    return b.packets


def synthetic_pcap_bytes(kind="mixed", seed=0):
    buffer = io.BytesIO()
    writer = PcapWriter(buffer, linktype=1, sync=True)
    for pkt in build_packets(kind, seed):
        writer.write(pkt)
    writer.flush()
    return buffer.getvalue()
