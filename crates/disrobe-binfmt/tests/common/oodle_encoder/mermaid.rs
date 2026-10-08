use super::LzStyle;
use super::entropy::encode_or_store;
use super::lz::{Matcher, literal};

const HALF_SPAN: usize = 0x1_0000;
const MIN_NEAR: usize = 4;
const MIN_FAR: usize = 8;

struct Streams {
    literals: Vec<u8>,
    commands: Vec<u8>,
    near: Vec<u16>,
    far: [Vec<u32>; 2],
    lengths: Vec<u8>,
    recent: usize,
    delta: bool,
}

impl Streams {
    fn long_length(&mut self, value: usize) {
        if value <= 251 {
            self.lengths.push(value as u8);
            return;
        }
        let low: usize = 252 + (value - 252) % 4;
        let high: usize = (value - low) / 4;
        assert!(high <= 0xFFFF, "Mermaid length {value} too long");
        self.lengths.push(low as u8);
        self.lengths.extend_from_slice(&(high as u16).to_le_bytes());
    }

    fn literals(&mut self, window: &[u8], from: usize, to: usize) {
        for p in from..to {
            self.literals
                .push(literal(window, p, self.delta.then_some(self.recent)));
        }
    }

    fn flush_literals(&mut self, window: &[u8], mut from: usize, to: usize) -> usize {
        while to - from >= 64 {
            let len: usize = (to - from).min(64 + 251);
            self.commands.push(0);
            self.long_length(len - 64);
            self.literals(window, from, from + len);
            from += len;
        }
        while to - from > 7 {
            self.commands.push(0x87);
            self.literals(window, from, from + 7);
            from += 7;
        }
        to - from
    }
}

fn encode_half(
    window: &[u8],
    half_start: usize,
    from: usize,
    end: usize,
    half: usize,
    streams: &mut Streams,
    style: &LzStyle,
) {
    let mut matcher: Matcher = Matcher::new(window.len());
    let mut pos: usize = from;
    let mut run_start: usize = pos;
    while pos < end {
        let near_ok = |distance: usize, len: usize| {
            (distance <= 0xFFFF && len >= MIN_NEAR) || (distance > 0xFFFF && len >= MIN_FAR)
        };
        let found: Option<(usize, usize)> = if end - pos >= MIN_NEAR {
            matcher.best(
                window,
                pos,
                end,
                &[streams.recent],
                style.max_match,
                &near_ok,
            )
        } else {
            None
        };
        let Some((distance, len)) = found else {
            pos += 1;
            continue;
        };
        let pending: usize = streams.flush_literals(window, run_start, pos);
        let literal_start: usize = pos - pending;
        if distance > 0xFFFF || (style.far_matches && len >= MIN_FAR && distance > pos - half_start)
        {
            if pending > 0 {
                streams.commands.push(0x80 | pending as u8);
                streams.literals(window, literal_start, pos);
            }
            streams.far[half].push((distance - (pos - half_start)) as u32);
            if len <= 28 {
                streams.commands.push((len - 5) as u8);
            } else {
                streams.commands.push(2);
                streams.long_length(len - 29);
            }
            streams.recent = distance;
        } else if len >= 91 {
            if pending > 0 {
                streams.commands.push(0x80 | pending as u8);
                streams.literals(window, literal_start, pos);
            }
            streams.commands.push(1);
            streams.long_length(len - 91);
            streams.near.push(distance as u16);
            streams.recent = distance;
        } else {
            let mut left: usize = len;
            let mut literals_left: usize = pending;
            let mut first: bool = true;
            while left > 0 {
                let piece: usize = if left > 15 && left - 15 < 3 {
                    left - 3
                } else {
                    left.min(15)
                };
                let fresh: bool = first && distance != streams.recent;
                streams.literals(window, pos - literals_left, pos);
                let mut command: u8 = ((piece << 3) | literals_left) as u8;
                if fresh {
                    streams.near.push(distance as u16);
                    streams.recent = distance;
                } else {
                    command |= 0x80;
                }
                streams.commands.push(command);
                literals_left = 0;
                left -= piece;
                first = false;
            }
        }
        pos += len;
        run_start = pos;
    }
    let pending: usize = streams.flush_literals(window, run_start, end);
    streams.literals(window, end - pending, end);
}

pub fn encode_sub_block(
    window: &[u8],
    start: usize,
    end: usize,
    delta: bool,
    style: &LzStyle,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let from: usize = if start == 0 {
        out.extend_from_slice(&window[..8]);
        8
    } else {
        start
    };
    let mut streams: Streams = Streams {
        literals: Vec::new(),
        commands: Vec::new(),
        near: Vec::new(),
        far: [Vec::new(), Vec::new()],
        lengths: Vec::new(),
        recent: 8,
        delta,
    };
    let first_end: usize = (start + HALF_SPAN).min(end);
    encode_half(window, start, from, first_end, 0, &mut streams, style);
    let split: usize = streams.commands.len();
    if first_end < end {
        encode_half(window, first_end, first_end, end, 1, &mut streams, style);
    }
    out.extend(encode_or_store(&streams.literals, &style.literals, false));
    out.extend(encode_or_store(&streams.commands, &style.commands, false));
    if end - start > HALF_SPAN {
        out.extend_from_slice(&(split as u16).to_le_bytes());
    }
    if style.entropy_near_offsets {
        out.extend_from_slice(&0xFFFFu16.to_le_bytes());
        let high: Vec<u8> = streams.near.iter().map(|&v: &u16| (v >> 8) as u8).collect();
        let low: Vec<u8> = streams.near.iter().map(|&v: &u16| v as u8).collect();
        out.extend(encode_or_store(&high, &style.offsets, false));
        out.extend(encode_or_store(&low, &style.offsets, false));
    } else {
        out.extend_from_slice(&(streams.near.len() as u16).to_le_bytes());
        for &value in &streams.near {
            out.extend_from_slice(&value.to_le_bytes());
        }
    }
    let counts: [usize; 2] = [streams.far[0].len(), streams.far[1].len()];
    let field = |count: usize| count.min(4095) as u32;
    let packed: u32 = (field(counts[0]) << 12) | field(counts[1]);
    out.extend_from_slice(&packed.to_le_bytes()[..3]);
    for &count in &counts {
        if count >= 4095 {
            out.extend_from_slice(&(count as u16).to_le_bytes());
        }
    }
    for far in &streams.far {
        for &value in far {
            out.extend_from_slice(&value.to_le_bytes()[..3]);
        }
    }
    out.extend_from_slice(&streams.lengths);
    out
}
