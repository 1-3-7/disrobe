use super::bits::{MsbWriter, bit_length};

pub const MIN_DISTANCE: usize = 8;
const HASH_BITS: u32 = 14;
const CHAIN_LIMIT: usize = 32;

pub struct Matcher {
    head: Vec<usize>,
    prev: Vec<usize>,
    inserted: usize,
}

fn hash(window: &[u8], pos: usize) -> usize {
    let value: u32 = u32::from_le_bytes([
        window[pos],
        window[pos + 1],
        window[pos + 2],
        window[pos + 3],
    ]);
    (value.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)) as usize
}

impl Matcher {
    pub fn new(len: usize) -> Self {
        Self {
            head: vec![usize::MAX; 1 << HASH_BITS],
            prev: vec![usize::MAX; len],
            inserted: 0,
        }
    }

    pub fn advance(&mut self, window: &[u8], upto: usize) {
        while self.inserted < upto {
            let pos: usize = self.inserted;
            if pos + 4 <= window.len() {
                let h: usize = hash(window, pos);
                self.prev[pos] = self.head[h];
                self.head[h] = pos;
            }
            self.inserted += 1;
        }
    }

    pub fn best(
        &mut self,
        window: &[u8],
        pos: usize,
        end: usize,
        recent: &[usize],
        max_len: usize,
        accept: &dyn Fn(usize, usize) -> bool,
    ) -> Option<(usize, usize)> {
        self.advance(window, pos);
        let limit: usize = (end - pos).min(max_len);
        let extend = |distance: usize| -> usize {
            let mut len: usize = 0;
            while len < limit && window[pos + len] == window[pos + len - distance] {
                len += 1;
            }
            len
        };
        let mut best: Option<(usize, usize)> = None;
        let consider = |distance: usize, best: &mut Option<(usize, usize)>| {
            if distance < MIN_DISTANCE || distance > pos {
                return;
            }
            let len: usize = extend(distance);
            if accept(distance, len) && best.is_none_or(|(_, b): (usize, usize)| len > b) {
                *best = Some((distance, len));
            }
        };
        for &distance in recent {
            consider(distance, &mut best);
        }
        if pos + 4 <= window.len() {
            let mut candidate: usize = self.head[hash(window, pos)];
            let mut steps: usize = 0;
            while candidate != usize::MAX && steps < CHAIN_LIMIT {
                consider(pos - candidate, &mut best);
                candidate = self.prev[candidate];
                steps += 1;
            }
        }
        best
    }
}

pub enum Distance {
    Classic,
    Scaled { scale: u32 },
}

pub struct BitRegion {
    forward: MsbWriter,
    backward: MsbWriter,
}

impl BitRegion {
    pub fn new(long_count: usize) -> Self {
        let mut backward: MsbWriter = MsbWriter::new();
        let value: u32 = long_count as u32 + 1;
        let width: u32 = bit_length(value);
        backward.put(0, width - 1);
        backward.put(value, width);
        Self {
            forward: MsbWriter::new(),
            backward,
        }
    }

    const fn writer(&mut self, index: usize) -> &mut MsbWriter {
        if index.is_multiple_of(2) {
            &mut self.forward
        } else {
            &mut self.backward
        }
    }

    pub fn finish(self) -> Vec<u8> {
        let mut out: Vec<u8> = self.forward.finish();
        let mut back: Vec<u8> = self.backward.finish();
        back.reverse();
        out.extend(back);
        out
    }
}

pub fn pack_distances(
    distances: &[usize],
    mode: &Distance,
    region: &mut BitRegion,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let mut packed: Vec<u8> = Vec::with_capacity(distances.len());
    let mut low: Vec<u8> = Vec::new();
    for (i, &distance) in distances.iter().enumerate() {
        let writer: &mut MsbWriter = region.writer(i);
        match mode {
            Distance::Classic => {
                let shifted: usize = distance + 248;
                let q: usize = shifted >> 4;
                let n: u32 = bit_length(q as u32) - 1;
                assert!(
                    (4..=18).contains(&n),
                    "classic distance {distance} out of range"
                );
                packed.push((((n - 4) << 4) as usize | (shifted & 15)) as u8);
                writer.put((q - (1 << n)) as u32, n);
            }
            Distance::Scaled { scale } => {
                let scale: usize = *scale as usize;
                let base: usize = distance / scale;
                if scale > 1 {
                    low.push((distance % scale) as u8);
                }
                let raw: usize = base + 8;
                let bits: u32 = bit_length(raw as u32) - 4;
                packed.push(((bits << 3) as usize | ((raw >> bits) - 8)) as u8);
                writer.put((raw & ((1 << bits) - 1)) as u32, bits);
            }
        }
    }
    let low: Option<Vec<u8>> = match mode {
        Distance::Scaled { scale } if *scale > 1 => Some(low),
        _ => None,
    };
    (packed, low)
}

pub fn write_long_lengths(longs: &[usize], region: &mut BitRegion) {
    for (i, &value) in longs.iter().enumerate() {
        let shifted: u32 = value as u32 + 64;
        let width: u32 = bit_length(shifted);
        let writer: &mut MsbWriter = region.writer(i);
        writer.put(0, width - 7);
        writer.put(shifted, width);
    }
}

pub fn pack_length(value: usize, packed: &mut Vec<u8>, longs: &mut Vec<usize>) {
    if value >= 255 {
        packed.push(255);
        longs.push(value - 255);
    } else {
        packed.push(value as u8);
    }
}

pub fn literal(window: &[u8], pos: usize, delta: Option<usize>) -> u8 {
    delta.map_or(window[pos], |distance: usize| {
        window[pos].wrapping_sub(window[pos - distance])
    })
}
