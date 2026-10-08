use super::entropy::decode_bytes;
use super::lz::{Cursor, INITIAL_DISTANCE, copy_match, copy_prefix, write_literals};
use super::{Ctx, OodleError};

const HALF_SPAN: usize = 0x1_0000;
const FAR_EXTENDED: u32 = 0xC0_0000;

fn u16_le(src: &[u8], at: usize, what: &'static str) -> Result<usize, OodleError> {
    let bytes: &[u8] = src.get(at..at + 2).ok_or(OodleError::Malformed(what))?;
    Ok(usize::from(bytes[0]) | (usize::from(bytes[1]) << 8))
}

fn far_offsets(
    src: &[u8],
    at: &mut usize,
    count: usize,
    half_start: usize,
) -> Result<Vec<usize>, OodleError> {
    let mut offsets: Vec<usize> = Vec::with_capacity(count.min(src.len() / 3));
    for _ in 0..count {
        let bytes: &[u8] = src
            .get(*at..*at + 3)
            .ok_or(OodleError::Malformed("Mermaid far offsets truncated"))?;
        let mut value: usize =
            usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16);
        *at += 3;
        if half_start >= FAR_EXTENDED as usize - 1 && value >= FAR_EXTENDED as usize {
            let high: u8 = *src
                .get(*at)
                .ok_or(OodleError::Malformed("Mermaid far offsets truncated"))?;
            value += usize::from(high) << 22;
            *at += 1;
        }
        if value > half_start {
            return Err(OodleError::Malformed(
                "Mermaid far offset reaches before the window",
            ));
        }
        offsets.push(value);
    }
    Ok(offsets)
}

struct Half<'a> {
    start: usize,
    end: usize,
    commands: &'a [u8],
    far: &'a [usize],
}

struct State<'a> {
    literals: Cursor<'a>,
    near: std::slice::Iter<'a, usize>,
    lengths: Cursor<'a>,
    recent: usize,
    delta: bool,
}

impl State<'_> {
    fn long_length(&mut self) -> Result<usize, OodleError> {
        let mut length: usize = usize::from(self.lengths.next("Mermaid length stream runs out")?);
        if length > 251 {
            let extra: &[u8] = self.lengths.take(2, "Mermaid length stream runs out")?;
            length += 4 * (usize::from(extra[0]) | (usize::from(extra[1]) << 8));
        }
        Ok(length)
    }

    fn literals(&mut self, window: &mut [u8], pos: usize, len: usize) -> Result<(), OodleError> {
        let run: &[u8] = self.literals.take(len, "Mermaid literal stream runs out")?;
        write_literals(window, pos, run, self.delta.then_some(self.recent))
    }

    fn near(&mut self) -> Result<usize, OodleError> {
        self.near
            .next()
            .copied()
            .ok_or(OodleError::Malformed("Mermaid near offset stream runs out"))
    }

    fn run_half(
        &mut self,
        window: &mut [u8],
        half: &Half<'_>,
        first: bool,
    ) -> Result<(), OodleError> {
        let mut pos: usize = half.start + if first { 8 } else { 0 };
        let mut far: std::slice::Iter<'_, usize> = half.far.iter();
        let mut next_far = |pos: usize| -> Result<usize, OodleError> {
            let offset: usize = *far
                .next()
                .ok_or(OodleError::Malformed("Mermaid far offset stream runs out"))?;
            Ok(pos - half.start + offset)
        };
        let half_window: &mut [u8] = &mut window[..half.end];
        for &command in half.commands {
            if command >= 24 {
                let litlen: usize = usize::from(command & 7);
                self.literals(half_window, pos, litlen)?;
                pos += litlen;
                if command & 0x80 == 0 {
                    self.recent = self.near()?;
                }
                let len: usize = usize::from((command >> 3) & 0xF);
                copy_match(half_window, pos, self.recent, len)?;
                pos += len;
            } else if command > 2 {
                let distance: usize = next_far(pos)?;
                self.recent = distance;
                let len: usize = usize::from(command) + 5;
                copy_match(half_window, pos, distance, len)?;
                pos += len;
            } else if command == 0 {
                let len: usize = self.long_length()? + 64;
                self.literals(half_window, pos, len)?;
                pos += len;
            } else if command == 1 {
                let len: usize = self.long_length()? + 91;
                let distance: usize = self.near()?;
                self.recent = distance;
                copy_match(half_window, pos, distance, len)?;
                pos += len;
            } else {
                let len: usize = self.long_length()? + 29;
                let distance: usize = next_far(pos)?;
                self.recent = distance;
                copy_match(half_window, pos, distance, len)?;
                pos += len;
            }
        }
        if far.next().is_some() {
            return Err(OodleError::Malformed("Mermaid far offsets are left over"));
        }
        let tail: usize = half.end - pos;
        self.literals(half_window, pos, tail)
    }
}

pub(super) fn decode(
    ctx: &mut Ctx<'_>,
    src: &[u8],
    mode: u32,
    window: &mut [u8],
    start: usize,
) -> Result<(), OodleError> {
    if mode > 1 {
        return Err(OodleError::Malformed(
            "Mermaid sub-block mode is neither delta nor raw",
        ));
    }
    if src.len() < 10 {
        return Err(OodleError::Malformed("Mermaid sub-block is too short"));
    }
    ctx.bump(if mode == 0 {
        "mermaid:sub"
    } else {
        "mermaid:raw"
    });
    let count: usize = window.len() - start;
    let mut at: usize = copy_prefix(window, start, src)?;
    let mut literals: Vec<u8> = Vec::new();
    at += decode_bytes(ctx, &src[at..], count, &mut literals)?;
    let mut commands: Vec<u8> = Vec::new();
    at += decode_bytes(ctx, src.get(at..).unwrap_or(&[]), count, &mut commands)?;
    let split: usize = if count > HALF_SPAN {
        let split: usize = u16_le(src, at, "Mermaid command split truncated")?;
        at += 2;
        if split > commands.len() {
            return Err(OodleError::Malformed(
                "Mermaid command split lies past the commands",
            ));
        }
        split
    } else {
        commands.len()
    };
    let near_count: usize = u16_le(src, at, "Mermaid near offset count truncated")?;
    at += 2;
    let mut near: Vec<usize> = Vec::new();
    if near_count == 0xFFFF {
        ctx.bump("mermaid:entropy-near-offsets");
        let mut high: Vec<u8> = Vec::new();
        at += decode_bytes(ctx, src.get(at..).unwrap_or(&[]), count >> 1, &mut high)?;
        let mut low: Vec<u8> = Vec::new();
        at += decode_bytes(ctx, src.get(at..).unwrap_or(&[]), count >> 1, &mut low)?;
        if low.len() != high.len() {
            return Err(OodleError::Malformed(
                "Mermaid near offset halves differ in length",
            ));
        }
        near.extend(
            low.iter()
                .zip(&high)
                .map(|(&lo, &hi): (&u8, &u8)| usize::from(lo) + 256 * usize::from(hi)),
        );
    } else {
        for _ in 0..near_count {
            near.push(u16_le(src, at, "Mermaid near offsets truncated")?);
            at += 2;
        }
    }
    let bytes: &[u8] = src
        .get(at..at + 3)
        .ok_or(OodleError::Malformed("Mermaid far offset counts truncated"))?;
    let counts: u32 =
        u32::from(bytes[0]) | (u32::from(bytes[1]) << 8) | (u32::from(bytes[2]) << 16);
    at += 3;
    let (far_first, far_second): (Vec<usize>, Vec<usize>) = if counts == 0 {
        (Vec::new(), Vec::new())
    } else {
        let mut first_count: usize = (counts >> 12) as usize;
        let mut second_count: usize = (counts & 0xFFF) as usize;
        if first_count == 4095 {
            first_count = u16_le(src, at, "Mermaid far offset count truncated")?;
            at += 2;
        }
        if second_count == 4095 {
            second_count = u16_le(src, at, "Mermaid far offset count truncated")?;
            at += 2;
        }
        let first: Vec<usize> = far_offsets(src, &mut at, first_count, start)?;
        let second: Vec<usize> = far_offsets(src, &mut at, second_count, start + HALF_SPAN)?;
        (first, second)
    };
    let mut state: State<'_> = State {
        literals: Cursor::new(&literals),
        near: near.iter(),
        lengths: Cursor::new(src.get(at..).unwrap_or(&[])),
        recent: INITIAL_DISTANCE,
        delta: mode == 0,
    };
    let first_end: usize = start + count.min(HALF_SPAN);
    state.run_half(
        window,
        &Half {
            start,
            end: first_end,
            commands: &commands[..split],
            far: &far_first,
        },
        start == 0,
    )?;
    if first_end < window.len() {
        state.run_half(
            window,
            &Half {
                start: first_end,
                end: window.len(),
                commands: &commands[split..],
                far: &far_second,
            },
            false,
        )?;
    } else if split != commands.len() || !far_second.is_empty() {
        return Err(OodleError::Malformed(
            "Mermaid second-half streams exist without a second half",
        ));
    }
    if !state.lengths.finished() || !state.literals.finished() || state.near.next().is_some() {
        return Err(OodleError::Malformed(
            "Mermaid streams are not consumed exactly",
        ));
    }
    Ok(())
}
