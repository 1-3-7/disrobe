# Network captures

`disrobe capture <file>` decodes a saved capture without Wireshark: pcap (either byte order, microsecond or nanosecond timestamps), pcapng (any section byte order, several interfaces, `if_tsresol` timestamps), HAR 1.2 and Fiddler SAZ archives.

```sh
disrobe capture traffic.pcapng                 # flows, DNS, TLS client hellos, HTTP exchanges
disrobe capture traffic.pcap --extract bodies  # also write every HTTP response body
disrobe capture session.har --json
```

## What it reports

- Frames by link type: Ethernet (with up to four 802.1Q or 802.1ad tags), Linux cooked capture v1 and v2, raw IPv4 and IPv6, and BSD loopback.
- Protocol counts: IPv4, IPv6 (hop-by-hop, routing, destination-options, fragment and AH extension headers), TCP, UDP, ICMP, IP fragments and other EtherTypes.
- Endpoints with packet counts, and flows with client, server, packets and bytes in each direction, first and last timestamps, and the application recognised in the stream.
- TCP streams reassembled per direction from the initial sequence number: out-of-order segments are placed by sequence number, retransmissions and overlaps are deduplicated, and a stream with a hole is marked incomplete.
- DNS messages over UDP port 53: questions, and A, AAAA, CNAME, NS, PTR, MX and TXT answers, with compressed names.
- TLS ClientHello messages: server name (SNI), ALPN protocols, supported versions, and the JA3 fingerprint string and its MD5 hash, with GREASE values removed as the JA3 definition requires.
- HTTP/1.x exchanges, requests paired with responses: method, target, Host, status, content type, and bodies delimited by `Content-Length` or chunked transfer encoding. `--extract <dir>` writes each response body, decompressed when its `Content-Encoding` is gzip, deflate or br.
- HAR entries and SAZ sessions as the same HTTP exchange records.

## Evidence

The grader in `crates/disrobe-dataforensics/tests/capture_reference.rs` builds captures byte by byte with a Python script and records what it wrote: a DNS query and a response carrying a compressed CNAME and an A record, an HTTP flow whose request arrives in two out-of-order segments plus a retransmission and whose gzip response is sent with chunked encoding, a second request with a `Content-Length` body, a TLS ClientHello with GREASE values, SNI, ALPN, groups, point formats and supported versions, an ICMP packet, an IP fragment, and a VLAN-tagged IPv6 DNS query. The same packets are written as little-endian and big-endian pcap, as raw-IP pcap, and as pcapng split across an Ethernet interface and a Linux cooked-capture interface with nanosecond timestamps. Every DNS name and answer, every HTTP field and decoded body, the SNI, ALPN, supported versions and the JA3 string and hash (computed independently by the generator) must match, every TCP stream must reassemble without gaps, and the fragment and ICMP counts must match. A broken SNI length and an overwritten request line must not reproduce the original values (mutation controls), and 500 randomly corrupted and truncated captures must produce a report or a typed error.

## Limits

- IP fragments are counted, not reassembled.
- QUIC and TLS application data are encrypted; only the ClientHello is decoded.
- HTTP/2 and HTTP/3 frames are not decoded; such flows are listed with their TLS hello.
- Frames, flows, stream bytes (64 MiB per direction, 1 GiB in total), exchanges, body sizes and listed flows are bounded, and the report's `problems` list names every bound reached.
