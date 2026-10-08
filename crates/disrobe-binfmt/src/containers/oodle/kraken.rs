use super::entropy::decode_bytes;
use super::lz::{
    Cursor, INITIAL_DISTANCE, OffsetsAndLengths, copy_match, copy_prefix, unpack, write_literals,
};
use super::{Ctx, OodleError};

pub(super) fn decode(
    ctx: &mut Ctx<'_>,
    src: &[u8],
    mode: u32,
    window: &mut [u8],
    start: usize,
) -> Result<(), OodleError> {
    if mode > 1 {
        return Err(OodleError::Malformed(
            "Kraken sub-block mode is neither delta nor raw",
        ));
    }
    if src.len() < 13 {
        return Err(OodleError::Malformed("Kraken sub-block is too short"));
    }
    ctx.bump(if mode == 0 {
        "kraken:sub"
    } else {
        "kraken:raw"
    });
    let count: usize = window.len() - start;
    let mut at: usize = copy_prefix(window, start, src)?;
    if src[at] & 0x80 != 0 {
        return Err(OodleError::ExcessBytesUnsupported);
    }
    let mut literals: Vec<u8> = Vec::new();
    at += decode_bytes(ctx, &src[at..], count, &mut literals)?;
    let mut commands: Vec<u8> = Vec::new();
    at += decode_bytes(ctx, src.get(at..).unwrap_or(&[]), count, &mut commands)?;
    if src.len() - at < 3 {
        return Err(OodleError::Malformed("Kraken offset streams truncated"));
    }
    let mut scaling: u32 = 0;
    let mut packed_offsets: Vec<u8> = Vec::new();
    let mut low_bits: Option<Vec<u8>> = None;
    if src[at] & 0x80 != 0 {
        scaling = u32::from(src[at]) - 127;
        at += 1;
        ctx.bump("kraken:scaled-offsets");
        at += decode_bytes(ctx, &src[at..], commands.len(), &mut packed_offsets)?;
        if scaling != 1 {
            let mut low: Vec<u8> = Vec::new();
            at += decode_bytes(
                ctx,
                src.get(at..).unwrap_or(&[]),
                packed_offsets.len(),
                &mut low,
            )?;
            if low.len() != packed_offsets.len() {
                return Err(OodleError::Malformed(
                    "Kraken scaled offset low bytes have the wrong length",
                ));
            }
            low_bits = Some(low);
        }
    } else {
        at += decode_bytes(ctx, &src[at..], commands.len(), &mut packed_offsets)?;
    }
    let mut packed_lengths: Vec<u8> = Vec::new();
    at += decode_bytes(
        ctx,
        src.get(at..).unwrap_or(&[]),
        count >> 2,
        &mut packed_lengths,
    )?;
    let streams: OffsetsAndLengths = unpack(
        src.get(at..).unwrap_or(&[]),
        &packed_offsets,
        low_bits.as_deref(),
        scaling,
        &packed_lengths,
    )?;
    let delta: bool = mode == 0;
    let mut pos: usize = start + if start == 0 { 8 } else { 0 };
    let mut lits: Cursor<'_> = Cursor::new(&literals);
    let mut distances: std::slice::Iter<'_, usize> = streams.distances.iter();
    let mut lengths: std::slice::Iter<'_, usize> = streams.lengths.iter();
    let mut recent: [usize; 3] = [INITIAL_DISTANCE; 3];
    let mut last: usize = INITIAL_DISTANCE;
    for &command in &commands {
        let mut litlen: usize = usize::from(command & 3);
        if litlen == 3 {
            litlen = *lengths
                .next()
                .ok_or(OodleError::Malformed("Kraken length stream runs out"))?;
        }
        let run: &[u8] = lits.take(litlen, "Kraken literal stream runs out")?;
        write_literals(window, pos, run, delta.then_some(last))?;
        pos += litlen;
        let slot: usize = usize::from(command >> 6);
        let distance: usize = if slot == 3 {
            let fresh: usize = *distances
                .next()
                .ok_or(OodleError::Malformed("Kraken offset stream runs out"))?;
            recent = [fresh, recent[0], recent[1]];
            fresh
        } else {
            let chosen: usize = recent[slot];
            recent.copy_within(0..slot, 1);
            recent[0] = chosen;
            chosen
        };
        last = distance;
        let short: usize = usize::from((command >> 2) & 0xF);
        let len: usize = if short == 15 {
            14 + *lengths
                .next()
                .ok_or(OodleError::Malformed("Kraken length stream runs out"))?
        } else {
            short + 2
        };
        copy_match(window, pos, distance, len)?;
        pos += len;
    }
    if distances.next().is_some() || lengths.next().is_some() {
        return Err(OodleError::Malformed(
            "Kraken offset or length streams are left over",
        ));
    }
    let tail: &[u8] = lits.take(lits.remaining(), "Kraken literal stream runs out")?;
    if tail.len() != window.len() - pos {
        return Err(OodleError::Malformed(
            "Kraken literals do not fill the sub-block",
        ));
    }
    write_literals(window, pos, tail, delta.then_some(last))?;
    Ok(())
}
