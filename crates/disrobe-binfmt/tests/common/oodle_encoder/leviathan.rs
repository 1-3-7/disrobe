use super::LzStyle;
use super::entropy::{Form, MultiStyle, encode_multi, encode_or_store};
use super::lz::{BitRegion, Distance, Matcher, pack_distances, pack_length, write_long_lengths};

const MIN_MATCH: usize = 4;
const RECENT_SLOTS: usize = 7;
const MULTI_COMMAND_MARKER: u8 = 0x83;

fn stream_count(mode: u32) -> usize {
    match mode {
        0 | 1 => 1,
        2 => 2,
        3 => 4,
        4 | 5 => 16,
        _ => panic!("Leviathan literal mode {mode} does not exist"),
    }
}

fn push_literals(
    window: &[u8],
    from: usize,
    to: usize,
    mode: u32,
    last: usize,
    streams: &mut [Vec<u8>],
) {
    for p in from..to {
        let delta: u8 = window[p].wrapping_sub(window[p - last]);
        match mode {
            0 => streams[0].push(delta),
            1 => streams[0].push(window[p]),
            2 => streams[usize::from(p == from)].push(delta),
            3 => streams[p & 3].push(delta),
            4 => streams[usize::from(window[p - 1] >> 4)].push(window[p]),
            _ => streams[p & 15].push(delta),
        }
    }
}

pub fn encode_sub_block(
    window: &[u8],
    start: usize,
    end: usize,
    mode: u32,
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
    let mut streams: Vec<Vec<u8>> = vec![Vec::new(); stream_count(mode)];
    let mut single_commands: Vec<u8> = Vec::new();
    let mut multi_commands: Vec<Vec<u8>> = vec![Vec::new(); 8];
    let mut new_distances: Vec<usize> = Vec::new();
    let mut front: Vec<usize> = Vec::new();
    let mut back: Vec<usize> = Vec::new();
    let mut recent: [usize; RECENT_SLOTS] = [8; RECENT_SLOTS];
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
        push_literals(window, run_start, pos, mode, last, &mut streams);
        let lit_code: u8 = if litlen >= 3 {
            front.push(litlen - 3);
            3
        } else {
            litlen as u8
        };
        let slot: usize = recent
            .iter()
            .position(|&d: &usize| d == distance)
            .unwrap_or(RECENT_SLOTS);
        if slot == RECENT_SLOTS {
            new_distances.push(distance);
            recent.copy_within(0..RECENT_SLOTS - 1, 1);
        } else {
            recent.copy_within(0..slot, 1);
        }
        recent[0] = distance;
        last = distance;
        let match_code: u8 = if len <= 8 {
            (len - 2) as u8
        } else {
            back.push(len - 9);
            7
        };
        let command: u8 = match_code | (lit_code << 3) | ((slot as u8) << 5);
        if style.multi_commands {
            multi_commands[run_start & 7].push(command);
        } else {
            single_commands.push(command);
        }
        pos += len;
        run_start = pos;
    }
    push_literals(window, run_start, end, mode, last, &mut streams);
    let mut packed_lengths: Vec<u8> = Vec::new();
    let mut longs: Vec<usize> = Vec::new();
    for &value in front.iter().chain(back.iter().rev()) {
        pack_length(value, &mut packed_lengths, &mut longs);
    }
    let mut region: BitRegion = BitRegion::new(longs.len());
    let distance_mode: Distance = style
        .scale
        .map_or(Distance::Classic, |scale: u32| Distance::Scaled { scale });
    let (packed_offsets, low): (Vec<u8>, Option<Vec<u8>>) =
        pack_distances(&new_distances, &distance_mode, &mut region);
    write_long_lengths(&longs, &mut region);
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
    if streams.len() == 1 {
        out.extend(encode_or_store(&streams[0], &style.literals, false));
    } else {
        out.extend(
            encode_multi(&streams, &style.multi)
                .or_else(|| encode_multi(&streams, &MultiStyle::Plain(Form::Stored)))
                .expect("a plain multi-array always encodes"),
        );
    }
    if style.multi_commands {
        out.push(MULTI_COMMAND_MARKER);
        out.extend(
            encode_multi(&multi_commands, &style.multi)
                .or_else(|| encode_multi(&multi_commands, &MultiStyle::Plain(Form::Stored)))
                .expect("a plain multi-array always encodes"),
        );
    } else {
        out.extend(encode_or_store(&single_commands, &style.commands, true));
    }
    out.extend(region.finish());
    out
}
