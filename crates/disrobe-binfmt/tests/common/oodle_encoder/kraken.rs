use super::LzStyle;
use super::entropy::{Form, encode_or_store};
use super::lz::{
    BitRegion, Distance, Matcher, literal, pack_distances, pack_length, write_long_lengths,
};

const MIN_MATCH: usize = 4;

pub fn encode_sub_block(
    window: &[u8],
    start: usize,
    end: usize,
    delta: bool,
    style: &LzStyle,
) -> Vec<u8> {
    let mut matcher: Matcher = Matcher::new(window.len());
    let mut out: Vec<u8> = Vec::new();
    let mut pos: usize = if start == 0 {
        out.extend_from_slice(&window[..8]);
        8
    } else {
        start
    };
    let mut literals: Vec<u8> = Vec::new();
    let mut commands: Vec<u8> = Vec::new();
    let mut new_distances: Vec<usize> = Vec::new();
    let mut packed_lengths: Vec<u8> = Vec::new();
    let mut longs: Vec<usize> = Vec::new();
    let mut recent: [usize; 3] = [8; 3];
    let mut last: usize = 8;
    let mut run_start: usize = pos;
    while pos < end {
        let accept = |_: usize, len: usize| len >= MIN_MATCH;
        let found: Option<(usize, usize)> = if end - pos >= MIN_MATCH {
            matcher.best(window, pos, end, &recent, style.max_match, &accept)
        } else {
            None
        };
        let Some((distance, len)) = found else {
            pos += 1;
            continue;
        };
        let litlen: usize = pos - run_start;
        for p in run_start..pos {
            literals.push(literal(window, p, delta.then_some(last)));
        }
        let lit_code: u8 = if litlen >= 3 {
            pack_length(litlen - 3, &mut packed_lengths, &mut longs);
            3
        } else {
            litlen as u8
        };
        let slot: usize = recent
            .iter()
            .position(|&d: &usize| d == distance)
            .unwrap_or(3);
        if slot == 3 {
            new_distances.push(distance);
            recent = [distance, recent[0], recent[1]];
        } else {
            recent.copy_within(0..slot, 1);
            recent[0] = distance;
        }
        last = distance;
        let match_code: u8 = if len <= 16 {
            (len - 2) as u8
        } else {
            pack_length(len - 17, &mut packed_lengths, &mut longs);
            15
        };
        commands.push(lit_code | (match_code << 2) | ((slot as u8) << 6));
        pos += len;
        run_start = pos;
    }
    for p in run_start..end {
        literals.push(literal(window, p, delta.then_some(last)));
    }
    let mut region: BitRegion = BitRegion::new(longs.len());
    let distance_mode: Distance = style
        .scale
        .map_or(Distance::Classic, |scale: u32| Distance::Scaled { scale });
    let (packed_offsets, low): (Vec<u8>, Option<Vec<u8>>) =
        pack_distances(&new_distances, &distance_mode, &mut region);
    write_long_lengths(&longs, &mut region);
    out.extend(encode_or_store(&literals, &style.literals, true));
    out.extend(encode_or_store(&commands, &style.commands, false));
    match style.scale {
        None => out.extend(encode_or_store(&packed_offsets, &style.offsets, true)),
        Some(scale) => {
            out.push((scale + 127) as u8);
            out.extend(encode_or_store(&packed_offsets, &style.offsets, false));
            if let Some(low) = low {
                out.extend(encode_or_store(&low, &Form::Stored, false));
            }
        }
    }
    out.extend(encode_or_store(&packed_lengths, &style.lengths, false));
    out.extend(region.finish());
    out
}
