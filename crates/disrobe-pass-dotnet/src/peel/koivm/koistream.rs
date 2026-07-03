use std::collections::BTreeMap;

pub const KOI_HEADER_MAGIC: u32 = 0x6873_6966;

#[derive(Debug, Clone)]
pub struct KoiStream {
    pub ref_map: BTreeMap<u32, CodedToken>,
    pub str_map: BTreeMap<u32, String>,
    pub sigs: Vec<KoiSig>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodedToken {
    pub table: KoiTable,
    pub rid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KoiTable {
    TypeDef,
    TypeRef,
    TypeSpec,
    MemberRef,
    Method,
    Field,
    MethodSpec,
}

impl CodedToken {
    #[must_use]
    pub const fn decode(coded: u32) -> Option<Self> {
        let rid: u32 = coded >> 3;
        let table: KoiTable = match coded & 0x7 {
            1 => KoiTable::TypeDef,
            2 => KoiTable::TypeRef,
            3 => KoiTable::TypeSpec,
            4 => KoiTable::MemberRef,
            5 => KoiTable::Method,
            6 => KoiTable::Field,
            7 => KoiTable::MethodSpec,
            _ => return None,
        };
        Some(Self { table, rid })
    }

    #[must_use]
    pub const fn metadata_token(self) -> u32 {
        let table_byte: u32 = match self.table {
            KoiTable::TypeDef => 0x02,
            KoiTable::TypeRef => 0x01,
            KoiTable::TypeSpec => 0x1B,
            KoiTable::MemberRef => 0x0A,
            KoiTable::Method => 0x06,
            KoiTable::Field => 0x04,
            KoiTable::MethodSpec => 0x2B,
        };
        (table_byte << 24) | self.rid
    }
}

#[derive(Debug, Clone)]
pub struct KoiSig {
    pub id: u32,
    pub entry_offset: u32,
    pub entry_key: u8,
    pub is_export: bool,
    pub flags: u8,
    pub param_tokens: Vec<CodedToken>,
    pub ret_token: Option<CodedToken>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KoiStreamError {
    Truncated,
    BadMagic(u32),
    BadCodedToken,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8, KoiStreamError> {
        let b: u8 = *self.data.get(self.pos).ok_or(KoiStreamError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn u32_le(&mut self) -> Result<u32, KoiStreamError> {
        let end: usize = self.pos.checked_add(4).ok_or(KoiStreamError::Truncated)?;
        let slice: &[u8] = self
            .data
            .get(self.pos..end)
            .ok_or(KoiStreamError::Truncated)?;
        let value: u32 = u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        self.pos = end;
        Ok(value)
    }

    fn i32_le(&mut self) -> Result<i32, KoiStreamError> {
        Ok(self.u32_le()?.cast_signed())
    }

    fn compressed_uint(&mut self) -> Result<u32, KoiStreamError> {
        let mut value: u32 = 0;
        let mut shift: u32 = 0;
        loop {
            let b: u8 = self.u8()?;
            value |= u32::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return Err(KoiStreamError::Truncated);
            }
        }
        Ok(value)
    }

    fn utf16(&mut self, char_count: u32) -> Result<String, KoiStreamError> {
        let mut units: Vec<u16> =
            Vec::with_capacity(bounded_capacity(char_count, self.remaining(), 2));
        for _ in 0..char_count {
            let lo: u8 = self.u8()?;
            let hi: u8 = self.u8()?;
            units.push(u16::from_le_bytes([lo, hi]));
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

fn bounded_capacity(declared: u32, remaining: usize, min_record_bytes: usize) -> usize {
    let ceiling: usize = remaining
        .checked_div(min_record_bytes.max(1))
        .unwrap_or(0)
        .saturating_add(1);
    (declared as usize).min(ceiling)
}

pub fn parse_koistream(data: &[u8]) -> Result<KoiStream, KoiStreamError> {
    let mut cur: Cursor<'_> = Cursor::new(data);
    let magic: u32 = cur.u32_le()?;
    if magic != KOI_HEADER_MAGIC {
        return Err(KoiStreamError::BadMagic(magic));
    }
    let ref_count: i32 = cur.i32_le()?;
    let str_count: i32 = cur.i32_le()?;
    let sig_count: i32 = cur.i32_le()?;

    let mut ref_map: BTreeMap<u32, CodedToken> = BTreeMap::new();
    for _ in 0..ref_count.max(0) {
        let value: u32 = cur.compressed_uint()?;
        let coded: u32 = cur.compressed_uint()?;
        let token: CodedToken = CodedToken::decode(coded).ok_or(KoiStreamError::BadCodedToken)?;
        ref_map.insert(value, token);
    }

    let mut str_map: BTreeMap<u32, String> = BTreeMap::new();
    for _ in 0..str_count.max(0) {
        let value: u32 = cur.compressed_uint()?;
        let len: u32 = cur.compressed_uint()?;
        let text: String = cur.utf16(len)?;
        str_map.insert(value, text);
    }

    let sig_total: u32 = sig_count.max(0).cast_unsigned();
    let mut sigs: Vec<KoiSig> = Vec::with_capacity(bounded_capacity(sig_total, cur.remaining(), 8));
    for _ in 0..sig_total {
        let id: u32 = cur.compressed_uint()?;
        let entry_offset: u32 = cur.u32_le()?;
        let is_export: bool = entry_offset != 0;
        let entry_key: u8 = if is_export {
            let key: u32 = cur.u32_le()?;
            (key & 0xFF) as u8
        } else {
            0
        };
        let flags: u8 = cur.u8()?;
        let param_count: u32 = cur.compressed_uint()?;
        let mut param_tokens: Vec<CodedToken> =
            Vec::with_capacity(bounded_capacity(param_count, cur.remaining(), 1));
        for _ in 0..param_count {
            let coded: u32 = cur.compressed_uint()?;
            param_tokens.push(CodedToken::decode(coded).ok_or(KoiStreamError::BadCodedToken)?);
        }
        let ret_coded: u32 = cur.compressed_uint()?;
        let ret_token: Option<CodedToken> = CodedToken::decode(ret_coded);

        sigs.push(KoiSig {
            id,
            entry_offset,
            entry_key,
            is_export,
            flags,
            param_tokens,
            ret_token,
        });
    }

    Ok(KoiStream {
        ref_map,
        str_map,
        sigs,
        raw: data.to_vec(),
    })
}

impl KoiStream {
    #[must_use]
    pub fn sig_by_id(&self, id: u32) -> Option<&KoiSig> {
        self.sigs.iter().find(|s: &&KoiSig| s.id == id)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn real_koistream() -> Vec<u8> {
        let mut path: std::path::PathBuf = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("../../corpus/dotnet/koivm/KoiSample.koistream.bin");
        std::fs::read(path).unwrap()
    }

    #[test]
    fn parses_real_koistream_header() {
        let bytes: Vec<u8> = real_koistream();
        let stream: KoiStream = parse_koistream(&bytes).unwrap();
        assert_eq!(stream.ref_map.len(), 0);
        assert_eq!(stream.str_map.len(), 1);
        assert_eq!(stream.sigs.len(), 7);
    }

    #[test]
    fn export_sigs_carry_entry_offsets() {
        let bytes: Vec<u8> = real_koistream();
        let stream: KoiStream = parse_koistream(&bytes).unwrap();
        for id in 2u32..=7 {
            let sig: &KoiSig = stream.sig_by_id(id).expect("export sig present");
            assert!(sig.is_export, "id {id} should be an exported method");
            assert!(
                (sig.entry_offset as usize) < bytes.len(),
                "id {id} entry offset {} must point inside #Koi (len {})",
                sig.entry_offset,
                bytes.len()
            );
        }
    }

    #[test]
    fn empty_string_is_id_one() {
        let bytes: Vec<u8> = real_koistream();
        let stream: KoiStream = parse_koistream(&bytes).unwrap();
        assert_eq!(stream.str_map.get(&1).map(String::as_str), Some(""));
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes: [u8; 16] = [0u8; 16];
        assert!(matches!(
            parse_koistream(&bytes),
            Err(KoiStreamError::BadMagic(0))
        ));
    }

    fn header_with_counts(ref_count: i32, str_count: i32, sig_count: i32) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::with_capacity(16);
        bytes.extend_from_slice(&KOI_HEADER_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&ref_count.to_le_bytes());
        bytes.extend_from_slice(&str_count.to_le_bytes());
        bytes.extend_from_slice(&sig_count.to_le_bytes());
        bytes
    }

    #[test]
    fn inflated_sig_count_is_bounded_not_oom() {
        let bytes: Vec<u8> = header_with_counts(0, 0, 0x7FFF_FFFF);
        assert!(matches!(
            parse_koistream(&bytes),
            Err(KoiStreamError::Truncated)
        ));
    }

    #[test]
    fn inflated_ref_count_is_bounded_not_oom() {
        let bytes: Vec<u8> = header_with_counts(0x7FFF_FFFF, 0, 0);
        assert!(matches!(
            parse_koistream(&bytes),
            Err(KoiStreamError::Truncated)
        ));
    }

    #[test]
    fn inflated_str_char_count_is_bounded_not_oom() {
        let mut bytes: Vec<u8> = header_with_counts(0, 1, 0);
        bytes.push(0x01);
        bytes.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x7F]);
        assert!(matches!(
            parse_koistream(&bytes),
            Err(KoiStreamError::Truncated)
        ));
    }

    #[test]
    fn bounded_capacity_clamps_to_remaining() {
        assert_eq!(bounded_capacity(0x7FFF_FFFF, 16, 8), 3);
        assert_eq!(bounded_capacity(2, 1024, 8), 2);
        assert_eq!(bounded_capacity(0x7FFF_FFFF, 0, 8), 1);
    }
}
