mod app;
mod archive;
mod container;
mod flows;
mod packet;

use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::Serialize;

pub use app::{ClientHello, DnsAnswer, DnsMessage, DnsQuestion};
use app::{HttpMessage, client_hello, decoded_body, dns, http_messages, looks_like_http_request};
pub use container::ContainerKind;
use container::Frame;
use flows::{Flow, FlowKey, socket};
use packet::{Network, Packet, TCP_SYN, Transport, decode};

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("not a capture: no pcap, pcapng, HAR or SAZ signature")]
    Unrecognized,
    #[error("truncated: {0}")]
    Truncated(String),
    #[error("malformed capture: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureLimits {
    pub frames: usize,
    pub frame_bytes: usize,
    pub flows: usize,
    pub stream_bytes: usize,
    pub total_stream_bytes: usize,
    pub exchanges: usize,
    pub listed: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            frames: 10_000_000,
            frame_bytes: 256 * 1024,
            flows: 1_000_000,
            stream_bytes: 64 * 1024 * 1024,
            total_stream_bytes: 1024 * 1024 * 1024,
            exchanges: 100_000,
            listed: 10_000,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaptureOptions {
    pub limits: CaptureLimits,
    pub keep_bodies: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureFormat {
    Pcap,
    Pcapng,
    Har,
    Saz,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowReport {
    pub protocol: String,
    pub client: String,
    pub server: String,
    pub packets: u64,
    pub client_bytes: u64,
    pub server_bytes: u64,
    pub first_ns: u64,
    pub last_ns: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    pub stream_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsHandshake {
    pub client: String,
    pub server: String,
    pub hello: ClientHello,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DnsEvent {
    pub client: String,
    pub server: String,
    pub message: DnsMessage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HttpExchange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    pub method: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub request_body_bytes: usize,
    pub response_body_bytes: usize,
    pub response_body_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExtractedBody {
    pub exchange: usize,
    pub content_type: Option<String>,
    #[serde(skip)]
    pub bytes: Vec<u8>,
    pub decoded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureReport {
    pub format: CaptureFormat,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerKind>,
    pub frames: u64,
    pub link_types: BTreeMap<u16, u64>,
    pub protocols: BTreeMap<String, u64>,
    pub endpoints: BTreeMap<String, u64>,
    pub flows: Vec<FlowReport>,
    pub dns: Vec<DnsEvent>,
    pub tls: Vec<TlsHandshake>,
    pub http: Vec<HttpExchange>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub bodies: Vec<ExtractedBody>,
    pub problems: Vec<String>,
}

pub fn inspect(bytes: &[u8], options: &CaptureOptions) -> Result<CaptureReport, CaptureError> {
    let limits: &CaptureLimits = &options.limits;
    if let Some(kind) = container::detect(bytes) {
        return Ok(packets(bytes, kind, options));
    }
    let (format, http): (CaptureFormat, Vec<HttpExchange>) = if archive::looks_like_saz(bytes) {
        (CaptureFormat::Saz, archive::saz(bytes, limits)?)
    } else if archive::looks_like_har(bytes) {
        (CaptureFormat::Har, archive::har(bytes, limits)?)
    } else {
        return Err(CaptureError::Unrecognized);
    };
    let mut endpoints: BTreeMap<String, u64> = BTreeMap::new();
    for exchange in &http {
        if let Some(host) = &exchange.host {
            *endpoints.entry(host.clone()).or_default() += 1;
        }
    }
    Ok(CaptureReport {
        format,
        container: None,
        frames: 0,
        link_types: BTreeMap::new(),
        protocols: BTreeMap::new(),
        endpoints,
        flows: Vec::new(),
        dns: Vec::new(),
        tls: Vec::new(),
        http,
        bodies: Vec::new(),
        problems: Vec::new(),
    })
}

fn packets(bytes: &[u8], kind: ContainerKind, options: &CaptureOptions) -> CaptureReport {
    let limits: &CaptureLimits = &options.limits;
    let mut problems: Vec<String> = Vec::new();
    let frames: Vec<Frame<'_>> = container::frames(bytes, kind, limits, &mut problems)
        .unwrap_or_else(|error: CaptureError| {
            problems.push(error.to_string());
            Vec::new()
        });
    let mut link_types: BTreeMap<u16, u64> = BTreeMap::new();
    let mut protocols: BTreeMap<String, u64> = BTreeMap::new();
    let mut endpoints: BTreeMap<String, u64> = BTreeMap::new();
    let mut flow_table: BTreeMap<FlowKey, Flow> = BTreeMap::new();
    let mut budget: usize = limits.total_stream_bytes;
    let mut dns_events: Vec<DnsEvent> = Vec::new();
    for frame in &frames {
        *link_types.entry(frame.link).or_default() += 1;
        let packet: Packet<'_> = decode(frame.link, frame.data);
        let network: &str = match packet.network {
            Network::Ipv4 => "ipv4",
            Network::Ipv6 => "ipv6",
            Network::Arp => "arp",
            Network::Other(_) => "other-ethertype",
            Network::Unknown => "undecoded",
        };
        *protocols.entry(network.to_owned()).or_default() += 1;
        let (Some(src), Some(dst)) = (packet.src, packet.dst) else {
            continue;
        };
        *endpoints.entry(src.to_string()).or_default() += 1;
        *endpoints.entry(dst.to_string()).or_default() += 1;
        let (protocol, src_port, dst_port, payload, seq, flags): (u8, u16, u16, &[u8], u32, u8) =
            match packet.transport {
                Transport::Tcp {
                    src_port,
                    dst_port,
                    seq,
                    flags,
                    payload,
                } => (6, src_port, dst_port, payload, seq, flags),
                Transport::Udp {
                    src_port,
                    dst_port,
                    payload,
                } => (17, src_port, dst_port, payload, 0, 0),
                Transport::Icmp => {
                    *protocols.entry("icmp".to_owned()).or_default() += 1;
                    continue;
                }
                Transport::Fragment => {
                    *protocols.entry("ip-fragment".to_owned()).or_default() += 1;
                    continue;
                }
                Transport::Other(number) => {
                    *protocols
                        .entry(format!("ip-protocol-{number}"))
                        .or_default() += 1;
                    continue;
                }
                Transport::None => continue,
            };
        *protocols
            .entry(if protocol == 6 { "tcp" } else { "udp" }.to_owned())
            .or_default() += 1;
        let source: SocketAddr = socket(src, src_port);
        let destination: SocketAddr = socket(dst, dst_port);
        if protocol == 17
            && (src_port == 53 || dst_port == 53)
            && let Some(message) = dns(payload)
        {
            {
                let (client, server): (SocketAddr, SocketAddr) = if message.response {
                    (destination, source)
                } else {
                    (source, destination)
                };
                dns_events.push(DnsEvent {
                    client: client.to_string(),
                    server: server.to_string(),
                    message,
                });
            }
        }
        let key: FlowKey = FlowKey::new(protocol, source, destination);
        if !flow_table.contains_key(&key) && flow_table.len() >= limits.flows {
            continue;
        }
        let syn_only: bool = protocol == 6 && flags & TCP_SYN != 0 && flags & 0x10 == 0;
        let flow: &mut Flow = flow_table
            .entry(key)
            .or_insert_with(|| Flow::new(source, destination, syn_only, frame.ts_ns));
        flow.last_ns = flow.last_ns.max(frame.ts_ns);
        flow.first_ns = flow.first_ns.min(frame.ts_ns);
        let direction: &mut flows::Direction = flow.direction(source);
        direction.packets += 1;
        direction.bytes += payload.len() as u64;
        if protocol == 6 {
            direction.add_segment(seq, flags, payload, limits.stream_bytes, &mut budget);
        }
    }
    let mut flows: Vec<FlowReport> = Vec::new();
    let mut tls: Vec<TlsHandshake> = Vec::new();
    let mut http: Vec<HttpExchange> = Vec::new();
    let mut bodies: Vec<ExtractedBody> = Vec::new();
    for (key, flow) in &flow_table {
        let client: String = flow.client.to_string();
        let server: String = flow.server.to_string();
        let mut application: Option<String> = None;
        let mut complete: bool = true;
        if key.protocol == 6 {
            let (upstream, up_gap): (Vec<u8>, bool) = flow.to_server.reassemble();
            let (downstream, down_gap): (Vec<u8>, bool) = flow.to_client.reassemble();
            complete = !up_gap && !down_gap;
            if let Some(hello) = client_hello(&upstream) {
                application = Some("tls".to_owned());
                tls.push(TlsHandshake {
                    client: client.clone(),
                    server: server.clone(),
                    hello,
                });
            } else if looks_like_http_request(&upstream) {
                application = Some("http".to_owned());
                let requests: Vec<HttpMessage> = http_messages(&upstream, false, &[]);
                let methods: Vec<String> = requests.iter().map(archive::method).collect();
                let responses: Vec<HttpMessage> = http_messages(&downstream, true, &methods);
                for (index, request) in requests.iter().enumerate() {
                    if http.len() >= limits.exchanges {
                        break;
                    }
                    let response: Option<&HttpMessage> = responses.get(index);
                    if options.keep_bodies
                        && let Some(response) = response
                        && !response.body.is_empty()
                    {
                        let decoded: Option<Vec<u8>> = decoded_body(response);
                        bodies.push(ExtractedBody {
                            exchange: http.len(),
                            content_type: response.header("Content-Type").map(str::to_owned),
                            decoded: decoded.is_some(),
                            bytes: decoded.unwrap_or_else(|| response.body.clone()),
                        });
                    }
                    http.push(exchange(
                        Some(client.clone()),
                        Some(server.clone()),
                        request,
                        response,
                    ));
                }
            } else if flow.server.port() == 53 || flow.client.port() == 53 {
                application = Some("dns".to_owned());
            }
        } else if flow.server.port() == 53 || flow.client.port() == 53 {
            application = Some("dns".to_owned());
        }
        if flows.len() < limits.listed {
            flows.push(FlowReport {
                protocol: if key.protocol == 6 { "tcp" } else { "udp" }.to_owned(),
                client,
                server,
                packets: flow.to_server.packets + flow.to_client.packets,
                client_bytes: flow.to_server.bytes,
                server_bytes: flow.to_client.bytes,
                first_ns: flow.first_ns,
                last_ns: flow.last_ns,
                application,
                stream_complete: complete,
            });
        }
    }
    if flow_table.len() > limits.listed {
        problems.push(format!(
            "{} flows; the first {} are listed",
            flow_table.len(),
            limits.listed
        ));
    }
    CaptureReport {
        format: if matches!(kind, ContainerKind::Pcapng) {
            CaptureFormat::Pcapng
        } else {
            CaptureFormat::Pcap
        },
        container: Some(kind),
        frames: frames.len() as u64,
        link_types,
        protocols,
        endpoints,
        flows,
        dns: dns_events,
        tls,
        http,
        bodies,
        problems,
    }
}

fn exchange(
    client: Option<String>,
    server: Option<String>,
    request: &HttpMessage,
    response: Option<&HttpMessage>,
) -> HttpExchange {
    let mut parts = request.start_line.split(' ');
    let method: String = parts.next().unwrap_or_default().to_owned();
    let target: String = parts.next().unwrap_or_default().to_owned();
    HttpExchange {
        client,
        server,
        method,
        target,
        host: request.header("Host").map(str::to_owned),
        status: response
            .and_then(|r: &HttpMessage| r.start_line.split(' ').nth(1)?.parse::<u16>().ok()),
        content_type: response
            .and_then(|r: &HttpMessage| r.header("Content-Type"))
            .map(str::to_owned),
        request_body_bytes: request.body.len(),
        response_body_bytes: response.map_or(0, |r: &HttpMessage| r.body.len()),
        response_body_complete: response.is_some_and(|r: &HttpMessage| r.body_complete),
    }
}
