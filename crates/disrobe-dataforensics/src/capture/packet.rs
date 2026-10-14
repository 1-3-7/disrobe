use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const LINK_NULL: u16 = 0;
const LINK_ETHERNET: u16 = 1;
const LINK_RAW: u16 = 101;
const LINK_RAW_ALT: u16 = 12;
const LINK_RAW_OPENBSD: u16 = 14;
const LINK_LOOP: u16 = 108;
const LINK_SLL: u16 = 113;
const LINK_IPV4: u16 = 228;
const LINK_IPV6: u16 = 229;
const LINK_SLL2: u16 = 276;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_VLAN: [u16; 3] = [0x8100, 0x88a8, 0x9100];
const MAX_VLAN_TAGS: usize = 4;
const MAX_IPV6_EXTENSIONS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Network {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Transport<'a> {
    Tcp {
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
        payload: &'a [u8],
    },
    Udp {
        src_port: u16,
        dst_port: u16,
        payload: &'a [u8],
    },
    Icmp,
    Fragment,
    Other(u8),
    None,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Packet<'a> {
    pub(super) network: Network,
    pub(super) src: Option<IpAddr>,
    pub(super) dst: Option<IpAddr>,
    pub(super) transport: Transport<'a>,
}

pub(super) const TCP_SYN: u8 = 0x02;

fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn be32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

pub(super) fn decode(link: u16, data: &[u8]) -> Packet<'_> {
    let unknown: Packet<'_> = Packet {
        network: Network::Unknown,
        src: None,
        dst: None,
        transport: Transport::None,
    };
    let (ethertype, payload): (u16, &[u8]) = match link {
        LINK_ETHERNET => {
            let Some(mut ethertype) = be16(data, 12) else {
                return unknown;
            };
            let mut at: usize = 14;
            let mut tags: usize = 0;
            while ETHERTYPE_VLAN.contains(&ethertype) && tags < MAX_VLAN_TAGS {
                let Some(inner) = be16(data, at + 2) else {
                    return unknown;
                };
                ethertype = inner;
                at += 4;
                tags += 1;
            }
            (ethertype, data.get(at..).unwrap_or_default())
        }
        LINK_SLL => (
            be16(data, 14).unwrap_or(0),
            data.get(16..).unwrap_or_default(),
        ),
        LINK_SLL2 => (
            be16(data, 0).unwrap_or(0),
            data.get(20..).unwrap_or_default(),
        ),
        LINK_NULL | LINK_LOOP => {
            let family: u32 = data
                .get(..4)
                .and_then(|b: &[u8]| <[u8; 4]>::try_from(b).ok())
                .map_or(0, |raw: [u8; 4]| {
                    u32::from_le_bytes(raw).min(u32::from_be_bytes(raw))
                });
            let ethertype: u16 = match family {
                2 => ETHERTYPE_IPV4,
                24 | 28 | 30 => ETHERTYPE_IPV6,
                _ => 0,
            };
            (ethertype, data.get(4..).unwrap_or_default())
        }
        LINK_RAW | LINK_RAW_ALT | LINK_RAW_OPENBSD | LINK_IPV4 | LINK_IPV6 => {
            let ethertype: u16 = match data.first().map(|b: &u8| b >> 4) {
                Some(4) => ETHERTYPE_IPV4,
                Some(6) => ETHERTYPE_IPV6,
                _ => 0,
            };
            (ethertype, data)
        }
        _ => return unknown,
    };
    match ethertype {
        ETHERTYPE_IPV4 => ipv4(payload).unwrap_or(unknown),
        ETHERTYPE_IPV6 => ipv6(payload).unwrap_or(unknown),
        ETHERTYPE_ARP => Packet {
            network: Network::Arp,
            ..unknown
        },
        other => Packet {
            network: Network::Other(other),
            ..unknown
        },
    }
}

fn ipv4(data: &[u8]) -> Option<Packet<'_>> {
    let header_len: usize = usize::from(data.first()? & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }
    let total: usize = usize::from(be16(data, 2)?).clamp(header_len, data.len());
    let flags_offset: u16 = be16(data, 6)?;
    let more_fragments: bool = flags_offset & 0x2000 != 0;
    let offset: u16 = flags_offset & 0x1fff;
    let protocol: u8 = *data.get(9)?;
    let src: IpAddr = IpAddr::V4(Ipv4Addr::from(be32(data, 12)?));
    let dst: IpAddr = IpAddr::V4(Ipv4Addr::from(be32(data, 16)?));
    let body: &[u8] = data.get(header_len..total)?;
    let transport: Transport<'_> = if more_fragments || offset != 0 {
        Transport::Fragment
    } else {
        transport(protocol, body)
    };
    Some(Packet {
        network: Network::Ipv4,
        src: Some(src),
        dst: Some(dst),
        transport,
    })
}

fn ipv6(data: &[u8]) -> Option<Packet<'_>> {
    let payload_len: usize = usize::from(be16(data, 4)?);
    let mut next: u8 = *data.get(6)?;
    let src: [u8; 16] = data.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = data.get(24..40)?.try_into().ok()?;
    let end: usize = (40 + payload_len).min(data.len());
    let mut at: usize = 40;
    let mut fragment: bool = false;
    for _ in 0..MAX_IPV6_EXTENSIONS {
        match next {
            0 | 43 | 60 => {
                let len: usize = (usize::from(*data.get(at + 1)?) + 1) * 8;
                next = *data.get(at)?;
                at += len;
            }
            44 => {
                let offset_flags: u16 = be16(data, at + 2)?;
                fragment = offset_flags & 0xfff9 != 0;
                next = *data.get(at)?;
                at += 8;
            }
            51 => {
                let len: usize = (usize::from(*data.get(at + 1)?) + 2) * 4;
                next = *data.get(at)?;
                at += len;
            }
            _ => break,
        }
    }
    let body: &[u8] = data.get(at..end).unwrap_or_default();
    Some(Packet {
        network: Network::Ipv6,
        src: Some(IpAddr::V6(Ipv6Addr::from(src))),
        dst: Some(IpAddr::V6(Ipv6Addr::from(dst))),
        transport: if fragment {
            Transport::Fragment
        } else {
            transport(next, body)
        },
    })
}

fn transport(protocol: u8, body: &[u8]) -> Transport<'_> {
    match protocol {
        6 => {
            let (Some(src_port), Some(dst_port), Some(seq)) =
                (be16(body, 0), be16(body, 2), be32(body, 4))
            else {
                return Transport::Other(protocol);
            };
            let offset: usize = usize::from(body.get(12).copied().unwrap_or(0) >> 4) * 4;
            if offset < 20 {
                return Transport::Other(protocol);
            }
            Transport::Tcp {
                src_port,
                dst_port,
                seq,
                flags: body.get(13).copied().unwrap_or(0),
                payload: body.get(offset..).unwrap_or_default(),
            }
        }
        17 => {
            let (Some(src_port), Some(dst_port)) = (be16(body, 0), be16(body, 2)) else {
                return Transport::Other(protocol);
            };
            Transport::Udp {
                src_port,
                dst_port,
                payload: body.get(8..).unwrap_or_default(),
            }
        }
        1 | 58 => Transport::Icmp,
        other => Transport::Other(other),
    }
}
