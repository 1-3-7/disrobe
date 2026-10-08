use super::entropy::{decode_bytes, decode_multi_array};
use super::lz::{INITIAL_DISTANCE, OffsetsAndLengths, copy_match, copy_prefix, unpack};
use super::{Ctx, OodleError};

const MULTI_COMMAND_MARKER: u8 = 0x83;
const COMMAND_STREAMS: usize = 8;
const RECENT_SLOTS: usize = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LiteralMode {
    Sub,
    Raw,
    LamSub,
    SubAnd3,
    O1,
    SubAndF,
}

impl LiteralMode {
    const fn from_mode(mode: u32) -> Option<Self> {
        match mode {
            0 => Some(Self::Sub),
            1 => Some(Self::Raw),
            2 => Some(Self::LamSub),
            3 => Some(Self::SubAnd3),
            4 => Some(Self::O1),
            5 => Some(Self::SubAndF),
            _ => None,
        }
    }

    const fn streams(self) -> usize {
        match self {
            Self::Sub | Self::Raw => 1,
            Self::LamSub => 2,
            Self::SubAnd3 => 4,
            Self::O1 | Self::SubAndF => 16,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Sub => "leviathan:sub",
            Self::Raw => "leviathan:raw",
            Self::LamSub => "leviathan:lamsub",
            Self::SubAnd3 => "leviathan:sub-and-3",
            Self::O1 => "leviathan:o1",
            Self::SubAndF => "leviathan:sub-and-f",
        }
    }
}

struct Literals {
    mode: LiteralMode,
    streams: Vec<Vec<u8>>,
    cursors: Vec<usize>,
}

impl Literals {
    fn pull(&mut self, stream: usize) -> Result<u8, OodleError> {
        let cursor: &mut usize = &mut self.cursors[stream];
        let value: u8 = *self.streams[stream]
            .get(*cursor)
            .ok_or(OodleError::Malformed("Leviathan literal stream runs out"))?;
        *cursor += 1;
        Ok(value)
    }

    fn emit(
        &mut self,
        window: &mut [u8],
        pos: usize,
        len: usize,
        last: usize,
    ) -> Result<(), OodleError> {
        if len > window.len() - pos {
            return Err(OodleError::Malformed(
                "Leviathan literals run past the sub-block",
            ));
        }
        if last > pos {
            return Err(OodleError::Malformed(
                "Leviathan literal delta reaches before the window",
            ));
        }
        for i in 0..len {
            let at: usize = pos + i;
            let value: u8 = match self.mode {
                LiteralMode::Raw => self.pull(0)?,
                LiteralMode::Sub => self.pull(0)?.wrapping_add(window[at - last]),
                LiteralMode::LamSub => {
                    let stream: usize = usize::from(i == 0);
                    self.pull(stream)?.wrapping_add(window[at - last])
                }
                LiteralMode::SubAnd3 => self.pull(at & 3)?.wrapping_add(window[at - last]),
                LiteralMode::SubAndF => self.pull(at & 15)?.wrapping_add(window[at - last]),
                LiteralMode::O1 => self.pull(usize::from(window[at - 1] >> 4))?,
            };
            window[at] = value;
        }
        Ok(())
    }

    fn exhausted(&self) -> bool {
        self.streams
            .iter()
            .zip(&self.cursors)
            .all(|(stream, &cursor): (&Vec<u8>, &usize)| cursor == stream.len())
    }
}

enum Commands {
    Single(Vec<u8>),
    Multi(Vec<Vec<u8>>),
}

pub(super) fn decode(
    ctx: &mut Ctx<'_>,
    src: &[u8],
    mode: u32,
    window: &mut [u8],
    start: usize,
) -> Result<(), OodleError> {
    let literal_mode: LiteralMode = LiteralMode::from_mode(mode)
        .ok_or(OodleError::Malformed("Leviathan sub-block mode above 5"))?;
    if src.len() < 13 {
        return Err(OodleError::Malformed("Leviathan sub-block is too short"));
    }
    ctx.bump(literal_mode.label());
    let count: usize = window.len() - start;
    let mut at: usize = copy_prefix(window, start, src)?;
    let mut scaling: u32 = 0;
    let mut packed_offsets: Vec<u8> = Vec::new();
    let mut low_bits: Option<Vec<u8>> = None;
    if src[at] & 0x80 == 0 {
        at += decode_bytes(ctx, &src[at..], count / 3, &mut packed_offsets)?;
    } else {
        scaling = u32::from(src[at]) - 127;
        at += 1;
        ctx.bump("leviathan:scaled-offsets");
        at += decode_bytes(
            ctx,
            src.get(at..).unwrap_or(&[]),
            count / 3,
            &mut packed_offsets,
        )?;
        if scaling != 1 {
            let mut low: Vec<u8> = Vec::new();
            at += decode_bytes(ctx, src.get(at..).unwrap_or(&[]), count / 3, &mut low)?;
            if low.len() != packed_offsets.len() {
                return Err(OodleError::Malformed(
                    "Leviathan scaled offset low bytes have the wrong length",
                ));
            }
            low_bits = Some(low);
        }
    }
    let mut packed_lengths: Vec<u8> = Vec::new();
    at += decode_bytes(
        ctx,
        src.get(at..).unwrap_or(&[]),
        count / 5,
        &mut packed_lengths,
    )?;
    let streams: Vec<Vec<u8>> = if literal_mode.streams() == 1 {
        let mut literals: Vec<u8> = Vec::new();
        at += decode_bytes(ctx, src.get(at..).unwrap_or(&[]), count, &mut literals)?;
        vec![literals]
    } else {
        let (used, arrays): (usize, Vec<Vec<u8>>) = decode_multi_array(
            ctx,
            src.get(at..).unwrap_or(&[]),
            literal_mode.streams(),
            count,
        )?;
        at += used;
        arrays
    };
    let first: u8 = *src
        .get(at)
        .ok_or(OodleError::Malformed("Leviathan command stream missing"))?;
    let commands: Commands = if first & 0x80 == 0 {
        let mut commands: Vec<u8> = Vec::new();
        at += decode_bytes(ctx, &src[at..], count, &mut commands)?;
        Commands::Single(commands)
    } else if first == MULTI_COMMAND_MARKER {
        ctx.bump("leviathan:multi-command");
        at += 1;
        let (used, arrays): (usize, Vec<Vec<u8>>) =
            decode_multi_array(ctx, src.get(at..).unwrap_or(&[]), COMMAND_STREAMS, count)?;
        at += used;
        Commands::Multi(arrays)
    } else {
        return Err(OodleError::Malformed(
            "Leviathan command stream header is invalid",
        ));
    };
    let offsets_and_lengths: OffsetsAndLengths = unpack(
        src.get(at..).unwrap_or(&[]),
        &packed_offsets,
        low_bits.as_deref(),
        scaling,
        &packed_lengths,
    )?;
    let cursors: Vec<usize> = vec![0; streams.len()];
    let mut literals: Literals = Literals {
        mode: literal_mode,
        streams,
        cursors,
    };
    run(
        window,
        start,
        &commands,
        &offsets_and_lengths,
        &mut literals,
    )
}

fn run(
    window: &mut [u8],
    start: usize,
    commands: &Commands,
    offsets_and_lengths: &OffsetsAndLengths,
    literals: &mut Literals,
) -> Result<(), OodleError> {
    let mut pos: usize = start + if start == 0 { 8 } else { 0 };
    let lengths: &[usize] = &offsets_and_lengths.lengths;
    let mut front: usize = 0;
    let mut back: usize = lengths.len();
    let mut distances: std::slice::Iter<'_, usize> = offsets_and_lengths.distances.iter();
    let mut recent: [usize; RECENT_SLOTS] = [INITIAL_DISTANCE; RECENT_SLOTS];
    let mut last: usize = INITIAL_DISTANCE;
    let total: usize = match commands {
        Commands::Single(stream) => stream.len(),
        Commands::Multi(streams) => streams.iter().map(Vec::len).sum(),
    };
    let mut multi_cursors: [usize; COMMAND_STREAMS] = [0; COMMAND_STREAMS];
    let mut single_cursor: usize = 0;
    for _ in 0..total {
        let command: u8 = match commands {
            Commands::Single(stream) => {
                let value: u8 = stream[single_cursor];
                single_cursor += 1;
                value
            }
            Commands::Multi(streams) => {
                let which: usize = pos & 7;
                let cursor: &mut usize = &mut multi_cursors[which];
                let value: u8 = *streams[which]
                    .get(*cursor)
                    .ok_or(OodleError::Malformed("Leviathan command stream runs out"))?;
                *cursor += 1;
                value
            }
        };
        let lit_cmd: usize = usize::from((command >> 3) & 3);
        let litlen: usize = if lit_cmd == 3 {
            if front >= back {
                return Err(OodleError::Malformed("Leviathan length stream runs out"));
            }
            front += 1;
            lengths[front - 1]
        } else {
            lit_cmd
        };
        literals.emit(window, pos, litlen, last)?;
        pos += litlen;
        let slot: usize = usize::from(command >> 5);
        let distance: usize = if slot == RECENT_SLOTS {
            let fresh: usize = *distances
                .next()
                .ok_or(OodleError::Malformed("Leviathan offset stream runs out"))?;
            recent.copy_within(0..RECENT_SLOTS - 1, 1);
            recent[0] = fresh;
            fresh
        } else {
            let chosen: usize = recent[slot];
            recent.copy_within(0..slot, 1);
            recent[0] = chosen;
            chosen
        };
        last = distance;
        let short: usize = usize::from(command & 7) + 2;
        let len: usize = if short == 9 {
            if front >= back {
                return Err(OodleError::Malformed("Leviathan length stream runs out"));
            }
            back -= 1;
            lengths[back] + 6
        } else {
            short
        };
        copy_match(window, pos, distance, len)?;
        pos += len;
    }
    if distances.next().is_some() || front != back {
        return Err(OodleError::Malformed(
            "Leviathan offset or length streams are left over",
        ));
    }
    literals.emit(window, pos, window.len() - pos, last)?;
    if !literals.exhausted() {
        return Err(OodleError::Malformed(
            "Leviathan literal streams are left over",
        ));
    }
    Ok(())
}
