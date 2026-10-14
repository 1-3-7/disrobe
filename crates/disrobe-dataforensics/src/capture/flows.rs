use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use super::packet::TCP_SYN;

const SEQUENCE_WINDOW: u32 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct FlowKey {
    pub(super) protocol: u8,
    pub(super) low: SocketAddr,
    pub(super) high: SocketAddr,
}

impl FlowKey {
    pub(super) fn new(protocol: u8, src: SocketAddr, dst: SocketAddr) -> Self {
        let (low, high): (SocketAddr, SocketAddr) =
            if src <= dst { (src, dst) } else { (dst, src) };
        Self {
            protocol,
            low,
            high,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct Direction {
    pub(super) packets: u64,
    pub(super) bytes: u64,
    base: Option<u32>,
    segments: BTreeMap<u32, Vec<u8>>,
    stored: usize,
    pub(super) dropped: bool,
}

#[derive(Debug)]
pub(super) struct Flow {
    pub(super) client: SocketAddr,
    pub(super) server: SocketAddr,
    pub(super) first_ns: u64,
    pub(super) last_ns: u64,
    pub(super) to_server: Direction,
    pub(super) to_client: Direction,
}

impl Flow {
    pub(super) fn new(src: SocketAddr, dst: SocketAddr, syn_only: bool, ts: u64) -> Self {
        let (client, server): (SocketAddr, SocketAddr) = if syn_only || dst.port() < src.port() {
            (src, dst)
        } else {
            (dst, src)
        };
        Self {
            client,
            server,
            first_ns: ts,
            last_ns: ts,
            to_server: Direction::default(),
            to_client: Direction::default(),
        }
    }

    pub(super) fn direction(&mut self, src: SocketAddr) -> &mut Direction {
        if src == self.client {
            &mut self.to_server
        } else {
            &mut self.to_client
        }
    }
}

impl Direction {
    pub(super) fn add_segment(
        &mut self,
        seq: u32,
        flags: u8,
        payload: &[u8],
        per_stream: usize,
        budget: &mut usize,
    ) {
        if flags & TCP_SYN != 0 {
            self.base = Some(seq.wrapping_add(1));
        }
        if payload.is_empty() {
            return;
        }
        let base: u32 = *self.base.get_or_insert(seq);
        let relative: u32 = seq.wrapping_sub(base);
        if relative >= SEQUENCE_WINDOW {
            return;
        }
        if self.stored + payload.len() > per_stream || payload.len() > *budget {
            self.dropped = true;
            return;
        }
        let keep: bool = self
            .segments
            .get(&relative)
            .is_none_or(|existing: &Vec<u8>| existing.len() < payload.len());
        if keep {
            if let Some(previous) = self.segments.insert(relative, payload.to_vec()) {
                self.stored -= previous.len();
                *budget += previous.len();
            }
            self.stored += payload.len();
            *budget -= payload.len();
        }
    }

    pub(super) fn reassemble(&self) -> (Vec<u8>, bool) {
        let mut out: Vec<u8> = Vec::with_capacity(self.stored);
        let mut next: u32 = self.segments.keys().next().copied().unwrap_or(0);
        let mut gap: bool = next != 0;
        for (offset, data) in &self.segments {
            if *offset > next {
                gap = true;
                break;
            }
            let skip: usize = (next - offset) as usize;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
                next = offset.wrapping_add(u32::try_from(data.len()).unwrap_or(u32::MAX));
            }
        }
        (out, gap || self.dropped)
    }
}

pub(super) const fn socket(address: IpAddr, port: u16) -> SocketAddr {
    SocketAddr::new(address, port)
}
