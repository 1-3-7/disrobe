use serde::Serialize;

use super::{CaptureError, CaptureLimits};

const PCAP_MICRO: u32 = 0xa1b2_c3d4;
const PCAP_NANO: u32 = 0xa1b2_3c4d;
const PCAPNG_SHB: u32 = 0x0a0d_0d0a;
const PCAPNG_BYTE_ORDER: u32 = 0x1a2b_3c4d;
const PCAPNG_IDB: u32 = 1;
const PCAPNG_PB: u32 = 2;
const PCAPNG_SPB: u32 = 3;
const PCAPNG_EPB: u32 = 6;
const OPTION_TSRESOL: u16 = 9;
const MAX_INTERFACES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ContainerKind {
    Pcap { nanosecond: bool, big_endian: bool },
    Pcapng,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct Frame<'a> {
    pub(super) ts_ns: u64,
    pub(super) link: u16,
    pub(super) data: &'a [u8],
}

#[derive(Debug, Clone, Copy)]
struct Interface {
    link: u16,
    snaplen: u32,
    ns_per_tick: f64,
}

pub(super) fn detect(bytes: &[u8]) -> Option<ContainerKind> {
    let head: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
    let big: u32 = u32::from_be_bytes(head);
    let little: u32 = u32::from_le_bytes(head);
    match (big, little) {
        (PCAP_MICRO, _) => Some(ContainerKind::Pcap {
            nanosecond: false,
            big_endian: true,
        }),
        (_, PCAP_MICRO) => Some(ContainerKind::Pcap {
            nanosecond: false,
            big_endian: false,
        }),
        (PCAP_NANO, _) => Some(ContainerKind::Pcap {
            nanosecond: true,
            big_endian: true,
        }),
        (_, PCAP_NANO) => Some(ContainerKind::Pcap {
            nanosecond: true,
            big_endian: false,
        }),
        (PCAPNG_SHB, _) => Some(ContainerKind::Pcapng),
        _ => None,
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    big_endian: bool,
}

impl Reader<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let raw: [u8; 2] = self.bytes.get(at..at + 2)?.try_into().ok()?;
        Some(if self.big_endian {
            u16::from_be_bytes(raw)
        } else {
            u16::from_le_bytes(raw)
        })
    }

    fn u32(&self, at: usize) -> Option<u32> {
        let raw: [u8; 4] = self.bytes.get(at..at + 4)?.try_into().ok()?;
        Some(if self.big_endian {
            u32::from_be_bytes(raw)
        } else {
            u32::from_le_bytes(raw)
        })
    }
}

pub(super) fn frames<'a>(
    bytes: &'a [u8],
    kind: ContainerKind,
    limits: &CaptureLimits,
    problems: &mut Vec<String>,
) -> Result<Vec<Frame<'a>>, CaptureError> {
    match kind {
        ContainerKind::Pcap {
            nanosecond,
            big_endian,
        } => pcap(bytes, nanosecond, big_endian, limits, problems),
        ContainerKind::Pcapng => pcapng(bytes, limits, problems),
    }
}

fn pcap<'a>(
    bytes: &'a [u8],
    nanosecond: bool,
    big_endian: bool,
    limits: &CaptureLimits,
    problems: &mut Vec<String>,
) -> Result<Vec<Frame<'a>>, CaptureError> {
    let reader: Reader<'_> = Reader { bytes, big_endian };
    let link: u32 = reader
        .u32(20)
        .ok_or_else(|| CaptureError::Truncated("the 24-byte pcap header".to_owned()))?;
    let link: u16 = u16::try_from(link & 0xffff).unwrap_or(u16::MAX);
    let mut out: Vec<Frame<'a>> = Vec::new();
    let mut at: usize = 24;
    while at + 16 <= bytes.len() {
        if out.len() >= limits.frames {
            problems.push(format!("stopped after {} frames", limits.frames));
            break;
        }
        let seconds: u64 = u64::from(reader.u32(at).unwrap_or(0));
        let fraction: u64 = u64::from(reader.u32(at + 4).unwrap_or(0));
        let captured: usize = reader.u32(at + 8).unwrap_or(0) as usize;
        if captured > limits.frame_bytes {
            problems.push(format!(
                "record at offset {at} declares {captured} captured bytes; stopped"
            ));
            break;
        }
        let Some(data) = bytes.get(at + 16..at + 16 + captured) else {
            problems.push(format!(
                "record at offset {at} runs past the end of the file"
            ));
            break;
        };
        let ts_ns: u64 = seconds
            .saturating_mul(1_000_000_000)
            .saturating_add(if nanosecond {
                fraction
            } else {
                fraction.saturating_mul(1000)
            });
        out.push(Frame { ts_ns, link, data });
        at += 16 + captured;
    }
    Ok(out)
}

fn pcapng<'a>(
    bytes: &'a [u8],
    limits: &CaptureLimits,
    problems: &mut Vec<String>,
) -> Result<Vec<Frame<'a>>, CaptureError> {
    let mut out: Vec<Frame<'a>> = Vec::new();
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut big_endian: bool = false;
    let mut at: usize = 0;
    while at + 12 <= bytes.len() {
        if out.len() >= limits.frames {
            problems.push(format!("stopped after {} frames", limits.frames));
            break;
        }
        let raw_type: [u8; 4] = bytes[at..at + 4]
            .try_into()
            .map_err(|_| CaptureError::Truncated("a block type".to_owned()))?;
        if u32::from_be_bytes(raw_type) == PCAPNG_SHB {
            let order: [u8; 4] = bytes
                .get(at + 8..at + 12)
                .and_then(|b: &[u8]| b.try_into().ok())
                .ok_or_else(|| CaptureError::Truncated("a section header".to_owned()))?;
            big_endian = match (u32::from_be_bytes(order), u32::from_le_bytes(order)) {
                (PCAPNG_BYTE_ORDER, _) => true,
                (_, PCAPNG_BYTE_ORDER) => false,
                _ => {
                    return Err(CaptureError::Malformed(format!(
                        "section header at {at} has no byte-order magic"
                    )));
                }
            };
            interfaces.clear();
        }
        let reader: Reader<'_> = Reader { bytes, big_endian };
        let block_type: u32 = reader.u32(at).unwrap_or(0);
        let total: usize = reader.u32(at + 4).unwrap_or(0) as usize;
        if total < 12 || total % 4 != 0 || at + total > bytes.len() {
            problems.push(format!("block at offset {at} has length {total}; stopped"));
            break;
        }
        let body: &[u8] = &bytes[at + 8..at + total - 4];
        let block: Reader<'_> = Reader {
            bytes: body,
            big_endian,
        };
        match block_type {
            PCAPNG_IDB => {
                if interfaces.len() >= MAX_INTERFACES {
                    problems.push("more than 4096 interfaces; later ones ignored".to_owned());
                } else {
                    let link: u16 = block.u16(0).unwrap_or(0);
                    let snaplen: u32 = block.u32(4).unwrap_or(0);
                    interfaces.push(Interface {
                        link,
                        snaplen,
                        ns_per_tick: tsresol(body.get(8..).unwrap_or_default(), big_endian),
                    });
                }
            }
            PCAPNG_EPB | PCAPNG_PB => {
                let (interface, ts_at, len_at, data_at): (usize, usize, usize, usize) =
                    if block_type == PCAPNG_EPB {
                        (block.u32(0).unwrap_or(u32::MAX) as usize, 4, 12, 20)
                    } else {
                        (usize::from(block.u16(0).unwrap_or(u16::MAX)), 4, 12, 20)
                    };
                let Some(iface) = interfaces.get(interface).copied() else {
                    problems.push(format!(
                        "packet block at {at} names interface {interface}, which is undeclared"
                    ));
                    at += total;
                    continue;
                };
                let high: u64 = u64::from(block.u32(ts_at).unwrap_or(0));
                let low: u64 = u64::from(block.u32(ts_at + 4).unwrap_or(0));
                let captured: usize = block.u32(len_at).unwrap_or(0) as usize;
                if let Some(data) = body.get(data_at..data_at + captured.min(limits.frame_bytes)) {
                    let ticks: u64 = (high << 32) | low;
                    out.push(Frame {
                        ts_ns: (ticks as f64 * iface.ns_per_tick) as u64,
                        link: iface.link,
                        data,
                    });
                } else {
                    problems.push(format!(
                        "packet block at {at} declares more data than it holds"
                    ));
                }
            }
            PCAPNG_SPB => {
                if let Some(iface) = interfaces.first().copied() {
                    let original: usize = block.u32(0).unwrap_or(0) as usize;
                    let limit: usize = if iface.snaplen == 0 {
                        usize::MAX
                    } else {
                        iface.snaplen as usize
                    };
                    let captured: usize = original
                        .min(limit)
                        .min(body.len().saturating_sub(4))
                        .min(limits.frame_bytes);
                    out.push(Frame {
                        ts_ns: 0,
                        link: iface.link,
                        data: &body[4..4 + captured],
                    });
                }
            }
            _ => {}
        }
        at += total;
    }
    Ok(out)
}

fn tsresol(options: &[u8], big_endian: bool) -> f64 {
    let reader: Reader<'_> = Reader {
        bytes: options,
        big_endian,
    };
    let mut at: usize = 0;
    while at + 4 <= options.len() {
        let code: u16 = reader.u16(at).unwrap_or(0);
        let len: usize = usize::from(reader.u16(at + 2).unwrap_or(0));
        if code == 0 {
            break;
        }
        if code == OPTION_TSRESOL && len >= 1 {
            let value: u8 = options.get(at + 4).copied().unwrap_or(6);
            let exponent: i32 = i32::from(value & 0x7f);
            return if value & 0x80 == 0 {
                1e9 / 10f64.powi(exponent)
            } else {
                1e9 / 2f64.powi(exponent)
            };
        }
        at += 4 + len.div_ceil(4) * 4;
    }
    1000.0
}
