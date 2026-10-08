use super::OodleError;
use super::bits::MsbReader;

pub(super) const MIN_MATCH_DISTANCE: usize = 8;
pub(super) const INITIAL_DISTANCE: usize = 8;
const MAX_LONG_LENGTHS: u32 = 512;

pub(super) struct OffsetsAndLengths {
    pub(super) distances: Vec<usize>,
    pub(super) lengths: Vec<usize>,
}

fn read_classic_distance(reader: &mut MsbReader<'_>, v: u32) -> u64 {
    if v < 0xF0 {
        let n: u32 = (v >> 4) + 4;
        let x: u64 = u64::from(reader.read(n));
        (((1u64 << n) + x) << 4) + u64::from(v & 0xF) - 248
    } else {
        let n: u32 = v - 0xF0 + 4;
        let x: u64 = u64::from(reader.read(n));
        let low: u64 = u64::from(reader.read(12));
        0x7F_0000 + (((1u64 << n) + x) << 12) + low
    }
}

fn read_long_length(reader: &mut MsbReader<'_>) -> Result<usize, OodleError> {
    let zeros: u32 = reader.leading_zeros();
    if zeros > 12 {
        return Err(OodleError::Malformed("long length prefix is too long"));
    }
    reader.skip(zeros);
    Ok(reader.read(zeros + 7) as usize - 64)
}

pub(super) fn unpack(
    region: &[u8],
    packed_offsets: &[u8],
    low_bits: Option<&[u8]>,
    scaling: u32,
    packed_lengths: &[u8],
) -> Result<OffsetsAndLengths, OodleError> {
    let mut a: MsbReader<'_> = MsbReader::forward(region);
    let mut b: MsbReader<'_> = MsbReader::backward(region);
    if b.peek(32) < 0x2000 {
        return Err(OodleError::Malformed(
            "long-length count prefix is too long",
        ));
    }
    let zeros: u32 = b.leading_zeros();
    b.skip(zeros);
    let long_count: u32 = b.read(zeros + 1) - 1;
    if long_count > MAX_LONG_LENGTHS {
        return Err(OodleError::Malformed(
            "more long lengths than a sub-block can hold",
        ));
    }
    let mut distances: Vec<usize> = Vec::with_capacity(packed_offsets.len());
    for (i, &packed) in packed_offsets.iter().enumerate() {
        let reader: &mut MsbReader<'_> = if i & 1 == 0 { &mut a } else { &mut b };
        let v: u32 = u32::from(packed);
        let distance: u64 = if scaling == 0 {
            read_classic_distance(reader, v)
        } else {
            let bits: u32 = v >> 3;
            if bits > 26 {
                return Err(OodleError::Malformed("scaled offset width above 26 bits"));
            }
            let raw: u64 = (u64::from(8 + (v & 7)) << bits) | u64::from(reader.read(bits));
            let base: u64 = raw - 8;
            match low_bits {
                Some(low) => {
                    let extra: u8 = *low
                        .get(i)
                        .ok_or(OodleError::Malformed("scaled offset low bytes run out"))?;
                    u64::from(scaling) * base + u64::from(extra)
                }
                None => base,
            }
        };
        distances.push(
            usize::try_from(distance).map_err(|_| OodleError::Malformed("offset overflows"))?,
        );
    }
    let mut long_lengths: Vec<usize> = Vec::with_capacity(long_count as usize);
    for i in 0..long_count {
        let reader: &mut MsbReader<'_> = if i & 1 == 0 { &mut a } else { &mut b };
        long_lengths.push(read_long_length(reader)?);
    }
    if a.consumed_bytes() + b.consumed_bytes() != region.len() {
        return Err(OodleError::Malformed(
            "offset and length bit streams do not meet",
        ));
    }
    let mut longs: std::slice::Iter<'_, usize> = long_lengths.iter();
    let mut lengths: Vec<usize> = Vec::with_capacity(packed_lengths.len());
    for &packed in packed_lengths {
        let value: usize = if packed == 255 {
            *longs
                .next()
                .ok_or(OodleError::Malformed("long lengths run out"))?
                + 255
        } else {
            usize::from(packed)
        };
        lengths.push(value + 3);
    }
    if longs.next().is_some() {
        return Err(OodleError::Malformed("long lengths are left over"));
    }
    Ok(OffsetsAndLengths { distances, lengths })
}

pub(super) fn copy_match(
    window: &mut [u8],
    pos: usize,
    distance: usize,
    len: usize,
) -> Result<(), OodleError> {
    if distance < MIN_MATCH_DISTANCE || distance > pos {
        return Err(OodleError::Malformed("match distance leaves the window"));
    }
    if len > window.len() - pos {
        return Err(OodleError::Malformed("match runs past the sub-block"));
    }
    let from: usize = pos - distance;
    if distance >= len {
        window.copy_within(from..from + len, pos);
    } else {
        for i in 0..len {
            window[pos + i] = window[from + i];
        }
    }
    Ok(())
}

pub(super) struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    pub(super) const fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    pub(super) fn next(&mut self, what: &'static str) -> Result<u8, OodleError> {
        let value: u8 = *self.data.get(self.at).ok_or(OodleError::Malformed(what))?;
        self.at += 1;
        Ok(value)
    }

    pub(super) fn take(&mut self, len: usize, what: &'static str) -> Result<&'a [u8], OodleError> {
        let slice: &'a [u8] = self
            .data
            .get(self.at..self.at + len)
            .ok_or(OodleError::Malformed(what))?;
        self.at += len;
        Ok(slice)
    }

    pub(super) const fn remaining(&self) -> usize {
        self.data.len() - self.at
    }

    pub(super) const fn finished(&self) -> bool {
        self.at == self.data.len()
    }
}

pub(super) fn write_literals(
    window: &mut [u8],
    pos: usize,
    literals: &[u8],
    sub_distance: Option<usize>,
) -> Result<(), OodleError> {
    if literals.len() > window.len() - pos {
        return Err(OodleError::Malformed("literals run past the sub-block"));
    }
    match sub_distance {
        None => window[pos..pos + literals.len()].copy_from_slice(literals),
        Some(distance) => {
            if distance > pos {
                return Err(OodleError::Malformed(
                    "literal delta reaches before the window",
                ));
            }
            for (i, &literal) in literals.iter().enumerate() {
                window[pos + i] = literal.wrapping_add(window[pos + i - distance]);
            }
        }
    }
    Ok(())
}

pub(super) fn copy_prefix(window: &mut [u8], pos: usize, src: &[u8]) -> Result<usize, OodleError> {
    if pos != 0 {
        return Ok(0);
    }
    if window.len() < 8 || src.len() < 8 {
        return Err(OodleError::Malformed(
            "first sub-block is shorter than its raw prefix",
        ));
    }
    window[..8].copy_from_slice(&src[..8]);
    Ok(8)
}
