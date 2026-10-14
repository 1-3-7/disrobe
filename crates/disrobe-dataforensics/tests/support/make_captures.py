import gzip
import hashlib
import json
import os
import struct
import sys
import zipfile

OUT = sys.argv[1]


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src, dst, proto, payload, ident=1, flags_offset=0x4000):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, flags_offset, 64, proto, 0,
                         bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def ipv6(src, dst, next_header, payload):
    import ipaddress
    return struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64) + ipaddress.IPv6Address(src).packed + ipaddress.IPv6Address(dst).packed + payload


def tcp(sport, dport, seq, ack, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def ethernet(payload, ethertype=0x0800, vlan=None):
    head = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01"
    if vlan is not None:
        head += struct.pack("!HH", 0x8100, vlan)
    return head + struct.pack("!H", ethertype) + payload


def sll(payload, ethertype=0x0800):
    return struct.pack("!HHH8sH", 0, 1, 6, b"\x02\x00\x00\x00\x00\x01\x00\x00", ethertype) + payload


def dns_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def dns_query(ident, name):
    return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)


def dns_response(ident, name, cname, address):
    body = struct.pack("!HHHHHH", ident, 0x8180, 1, 2, 0, 0) + dns_name(name) + struct.pack("!HH", 1, 1)
    target = dns_name(cname)
    body += b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 300, len(target)) + target
    cname_at = 12 + len(dns_name(name)) + 4 + 12
    body += struct.pack("!H", 0xC000 | cname_at) + struct.pack("!HHIH", 1, 1, 60, 4) + bytes(map(int, address.split(".")))
    return body


GREASE = 0x0A0A
CIPHERS = [GREASE, 0x1301, 0x1302, 0xC02B, 0xC02F]
GROUPS = [GREASE, 29, 23, 24]
POINT_FORMATS = [0]
VERSIONS = [GREASE, 0x0304, 0x0303]
ALPN = ["h2", "http/1.1"]
SNI = "secure.example.org"


def extension(kind, data):
    return struct.pack("!HH", kind, len(data)) + data


def client_hello():
    exts = [extension(GREASE, b"")]
    name = SNI.encode()
    exts.append(extension(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name))
    protos = b"".join(bytes([len(p)]) + p.encode() for p in ALPN)
    exts.append(extension(16, struct.pack("!H", len(protos)) + protos))
    exts.append(extension(10, struct.pack("!H", 2 * len(GROUPS)) + b"".join(struct.pack("!H", g) for g in GROUPS)))
    exts.append(extension(11, bytes([len(POINT_FORMATS)]) + bytes(POINT_FORMATS)))
    exts.append(extension(43, bytes([2 * len(VERSIONS)]) + b"".join(struct.pack("!H", v) for v in VERSIONS)))
    ext_bytes = b"".join(exts)
    body = struct.pack("!H", 0x0303) + bytes(range(32)) + b"\x20" + bytes(32)
    body += struct.pack("!H", 2 * len(CIPHERS)) + b"".join(struct.pack("!H", c) for c in CIPHERS)
    body += b"\x01\x00" + struct.pack("!H", len(ext_bytes)) + ext_bytes
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def ja3():
    def clean(values):
        return "-".join(str(v) for v in values if not ((v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)))
    extensions = [GREASE, 0, 16, 10, 11, 43]
    text = f"{0x0303},{clean(CIPHERS)},{clean(extensions)},{clean(GROUPS)},{clean(POINT_FORMATS)}"
    return text, hashlib.md5(text.encode()).hexdigest()


HTML = b"<html><body>hello from the reference capture</body></html>"


def http_flow(client, server, sport):
    request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: reference\r\n\r\n"
    compressed = gzip.compress(HTML, mtime=0)
    chunks = b"".join(f"{len(compressed[i:i + 20]):x}\r\n".encode() + compressed[i:i + 20] + b"\r\n" for i in range(0, len(compressed), 20)) + b"0\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks
    post = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello=world"
    created = b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nok"
    upstream = request + post
    downstream = response + created
    c_isn, s_isn = 1000, 50000
    segments = [
        (client, server, sport, 80, tcp(sport, 80, c_isn, 0, 0x02)),
        (server, client, 80, sport, tcp(80, sport, s_isn, c_isn + 1, 0x12)),
        (client, server, sport, 80, tcp(sport, 80, c_isn + 1, s_isn + 1, 0x10)),
        (client, server, sport, 80, tcp(sport, 80, c_isn + 1 + 30, s_isn + 1, 0x18, upstream[30:])),
        (client, server, sport, 80, tcp(sport, 80, c_isn + 1, s_isn + 1, 0x18, upstream[:30])),
        (client, server, sport, 80, tcp(sport, 80, c_isn + 1, s_isn + 1, 0x18, upstream[:30])),
    ]
    half = len(downstream) // 2
    segments.append((server, client, 80, sport, tcp(80, sport, s_isn + 1, c_isn + 1 + len(upstream), 0x18, downstream[:half])))
    segments.append((server, client, 80, sport, tcp(80, sport, s_isn + 1 + half, c_isn + 1 + len(upstream), 0x18, downstream[half:])))
    return [ipv4(src, dst, 6, segment) for src, dst, _, _, segment in segments]


def tls_flow(client, server, sport):
    hello = client_hello()
    return [
        ipv4(client, server, 6, tcp(sport, 443, 7000, 0, 0x02)),
        ipv4(server, client, 6, tcp(443, sport, 9000, 7001, 0x12)),
        ipv4(client, server, 6, tcp(sport, 443, 7001, 9001, 0x18, hello)),
    ]


def ipv4_packets():
    packets = []
    packets.append(ipv4("10.0.0.2", "8.8.8.8", 17, udp(5353, 53, dns_query(0x1234, "www.example.com"))))
    packets.append(ipv4("8.8.8.8", "10.0.0.2", 17, udp(53, 5353, dns_response(0x1234, "www.example.com", "example.com", "93.184.216.34"))))
    packets += http_flow("10.0.0.2", "93.184.216.34", 40000)
    packets += tls_flow("10.0.0.2", "1.1.1.1", 40001)
    packets.append(ipv4("10.0.0.2", "10.0.0.9", 1, b"\x08\x00\x00\x00\x00\x01\x00\x01"))
    packets.append(ipv4("10.0.0.2", "10.0.0.9", 17, b"fragmented-payload", ident=9, flags_offset=0x2000))
    return packets


def write_pcap(name, frames, link, big_endian=False):
    order = ">" if big_endian else "<"
    with open(os.path.join(OUT, name), "wb") as handle:
        handle.write(struct.pack(order + "IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link))
        for index, frame in enumerate(frames):
            handle.write(struct.pack(order + "IIII", 1700000000 + index, 250000, len(frame), len(frame)) + frame)


def pcapng_block(kind, body):
    pad = (-len(body)) % 4
    total = 12 + len(body) + pad
    return struct.pack(">II", kind, total) + body + b"\0" * pad + struct.pack(">I", total)


def write_pcapng(name, interfaces):
    blocks = [pcapng_block(0x0A0D0D0A, struct.pack(">IHHq", 0x1A2B3C4D, 1, 0, -1))]
    for link, _ in interfaces:
        options = struct.pack(">HHB3x", 9, 1, 9) + struct.pack(">HH", 0, 0)
        blocks.append(pcapng_block(1, struct.pack(">HHI", link, 0, 262144) + options))
    ts = 1_700_000_000_123_456_789
    for interface, (_, frames) in enumerate(interfaces):
        for frame in frames:
            ts += 1_000
            body = struct.pack(">IIIII", interface, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame
            blocks.append(pcapng_block(6, body))
    with open(os.path.join(OUT, name), "wb") as handle:
        handle.write(b"".join(blocks))


ipv4_frames = ipv4_packets()
eth = [ethernet(packet) for packet in ipv4_frames]
v6 = ipv6("2001:db8::1", "2001:db8::53", 17, udp(5454, 53, dns_query(0x7777, "v6.example.net")))
eth.append(ethernet(v6, ethertype=0x86DD, vlan=42))
write_pcap("capture.pcap", eth, 1)
write_pcap("capture-be.pcap", eth, 1, big_endian=True)
write_pcap("capture-raw.pcap", ipv4_frames, 101)
write_pcapng("capture.pcapng", [(1, eth[: len(eth) // 2]), (113, [sll(p) for p in ipv4_frames[len(eth) // 2:]] + [sll(v6, 0x86DD)])])

text, digest = ja3()
truth = {
    "dns_queries": ["www.example.com", "v6.example.net"],
    "dns_answers": [["www.example.com", 5, "example.com"], ["example.com", 1, "93.184.216.34"]],
    "http": [
        {"method": "GET", "target": "/index.html", "host": "example.com", "status": 200, "content_type": "text/html", "body": HTML.decode()},
        {"method": "POST", "target": "/submit", "host": "example.com", "status": 201, "content_type": "text/plain", "body": "ok"},
    ],
    "tls": {"sni": SNI, "alpn": ALPN, "ja3": text, "ja3_md5": digest, "supported_versions": [0x0304, 0x0303]},
    "tcp_flows": 2,
    "fragments": 1,
}

har = {"log": {"version": "1.2", "creator": {"name": "reference", "version": "1"}, "entries": [
    {"request": {"method": "GET", "url": "https://api.example.com/v1/items?limit=2", "headers": []},
     "response": {"status": 200, "content": {"mimeType": "application/json", "size": 13, "text": "{\"items\": []}"}},
     "serverIPAddress": "203.0.113.5"},
    {"request": {"method": "POST", "url": "https://login.example.com/session", "postData": {"text": "user=a"}},
     "response": {"status": 302, "content": {"mimeType": "text/html", "size": 0}}},
]}}
with open(os.path.join(OUT, "session.har"), "w", encoding="utf-8") as handle:
    json.dump(har, handle)
with zipfile.ZipFile(os.path.join(OUT, "session.saz"), "w") as saz:
    saz.writestr("raw/01_c.txt", b"GET http://legacy.example.com/old HTTP/1.1\r\nHost: legacy.example.com\r\n\r\n")
    saz.writestr("raw/01_s.txt", b"HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 9\r\n\r\nnot found")
    saz.writestr("raw/01_m.xml", b"<Session />")
truth["har"] = [["GET", "https://api.example.com/v1/items?limit=2", 200], ["POST", "https://login.example.com/session", 302]]
truth["saz"] = [["GET", "http://legacy.example.com/old", 404]]
with open(os.path.join(OUT, "truth.json"), "w", encoding="utf-8") as handle:
    json.dump(truth, handle)
print("ok")
