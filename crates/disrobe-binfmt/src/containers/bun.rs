use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const BUN_TRAILER: &[u8; 16] = b"\n---- Bun! ----\n";
const OFFSETS_LEN: usize = 32;
const MODULE_RECORD_LEN: usize = 52;
const BACK_SCAN_LIMIT: usize = 8 * 1024 * 1024;
const MAX_MODULES: usize = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BunOffsets {
    pub byte_count: u64,
    pub modules_offset: u32,
    pub modules_length: u32,
    pub entry_point_id: u32,
    pub exec_argv_offset: u32,
    pub exec_argv_length: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BunModule {
    pub name: String,
    pub contents_offset: u32,
    pub contents_length: u32,
    pub sourcemap_offset: u32,
    pub sourcemap_length: u32,
    pub bytecode_length: u32,
    pub encoding: u8,
    pub loader: u8,
    pub module_format: u8,
    pub is_entry: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BunStandalone {
    pub trailer_offset: u64,
    pub data_start: u64,
    pub offsets: BunOffsets,
    pub modules: Vec<BunModule>,
}

#[inline]
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let end: usize = at.checked_add(4)?;
    let slice: &[u8] = bytes.get(at..end)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[inline]
fn read_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end: usize = at.checked_add(8)?;
    let slice: &[u8] = bytes.get(at..end)?;
    Some(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

fn read_record_u32(bytes: &[u8], record: usize, offset: usize, err: &'static str) -> Result<u32> {
    let at: usize = record
        .checked_add(offset)
        .ok_or_else(|| Error::Decompression(err.to_owned()))?;
    read_u32(bytes, at).ok_or_else(|| Error::Decompression(err.to_owned()))
}

fn read_record_u8(bytes: &[u8], record: usize, offset: usize, err: &'static str) -> Result<u8> {
    let at: usize = record
        .checked_add(offset)
        .ok_or_else(|| Error::Decompression(err.to_owned()))?;
    bytes
        .get(at)
        .copied()
        .ok_or_else(|| Error::Decompression(err.to_owned()))
}

fn find_trailer(bytes: &[u8]) -> Option<usize> {
    let len: usize = bytes.len();
    if len < BUN_TRAILER.len() + OFFSETS_LEN {
        return None;
    }
    let scan_start: usize = len.saturating_sub(BACK_SCAN_LIMIT);
    let window: &[u8] = &bytes[scan_start..];
    let mut from: usize = window.len().saturating_sub(BUN_TRAILER.len());
    loop {
        if window[from..].starts_with(BUN_TRAILER) {
            return Some(scan_start + from);
        }
        if from == 0 {
            return None;
        }
        from -= 1;
    }
}

fn read_offsets(bytes: &[u8], trailer_offset: usize) -> Option<BunOffsets> {
    let base: usize = trailer_offset.checked_sub(OFFSETS_LEN)?;
    Some(BunOffsets {
        byte_count: read_u64(bytes, base)?,
        modules_offset: read_u32(bytes, base + 8)?,
        modules_length: read_u32(bytes, base + 12)?,
        entry_point_id: read_u32(bytes, base + 16)?,
        exec_argv_offset: read_u32(bytes, base + 20)?,
        exec_argv_length: read_u32(bytes, base + 24)?,
        flags: read_u32(bytes, base + 28)?,
    })
}

fn data_start_from(trailer_offset: usize, offsets: &BunOffsets) -> Option<usize> {
    let modules_length: usize = usize::try_from(offsets.modules_length).ok()?;
    let modules_offset: usize = usize::try_from(offsets.modules_offset).ok()?;
    let byte_count: usize = usize::try_from(offsets.byte_count).ok()?;
    let module_table_end: usize = trailer_offset.checked_sub(OFFSETS_LEN)?;
    let module_table_start: usize = module_table_end.checked_sub(modules_length)?;
    let data_start: usize = module_table_start.checked_sub(byte_count)?;
    if data_start.checked_add(modules_offset)? != module_table_start {
        return None;
    }
    Some(data_start)
}

pub fn detect_bun(bytes: &[u8]) -> Option<BunOffsets> {
    if bytes.len() < 64 {
        return None;
    }
    let mz_or_elf_or_macho: bool = bytes.starts_with(b"MZ")
        || bytes.starts_with(&[0x7f, b'E', b'L', b'F'])
        || bytes.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || bytes.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || bytes.starts_with(&[0xca, 0xfe, 0xba, 0xbe]);
    if !mz_or_elf_or_macho {
        return None;
    }
    let trailer: usize = find_trailer(bytes)?;
    let offsets: BunOffsets = read_offsets(bytes, trailer)?;
    let modules_length: usize = usize::try_from(offsets.modules_length).ok()?;
    if modules_length == 0 || !modules_length.is_multiple_of(MODULE_RECORD_LEN) {
        return None;
    }
    data_start_from(trailer, &offsets)?;
    Some(offsets)
}

pub fn parse_bun(bytes: &[u8]) -> Result<BunStandalone> {
    let trailer: usize = find_trailer(bytes)
        .ok_or_else(|| Error::Decompression("bun trailer not found".to_owned()))?;
    let offsets: BunOffsets = read_offsets(bytes, trailer)
        .ok_or_else(|| Error::Decompression("bun offsets struct truncated".to_owned()))?;
    let data_start: usize = data_start_from(trailer, &offsets)
        .ok_or_else(|| Error::Decompression("bun data_start out of range".to_owned()))?;
    let modules_length: usize = usize::try_from(offsets.modules_length)
        .map_err(|_| Error::Decompression("bun module table length out of range".to_owned()))?;
    if !modules_length.is_multiple_of(MODULE_RECORD_LEN) {
        return Err(Error::Decompression(
            "bun module table length is not a multiple of the record size".to_owned(),
        ));
    }
    let module_count: usize = modules_length / MODULE_RECORD_LEN;
    if module_count > MAX_MODULES {
        return Err(Error::Decompression(
            "bun module count exceeds sanity bound".to_owned(),
        ));
    }
    let modules_offset: usize = usize::try_from(offsets.modules_offset)
        .map_err(|_| Error::Decompression("bun module table offset out of range".to_owned()))?;
    let table_start: usize = data_start
        .checked_add(modules_offset)
        .ok_or_else(|| Error::Decompression("bun module table offset overflow".to_owned()))?;

    let resolve = |off: u32, len: u32| -> Option<&[u8]> {
        let start: usize = data_start.checked_add(usize::try_from(off).ok()?)?;
        let end: usize = start.checked_add(usize::try_from(len).ok()?)?;
        bytes.get(start..end)
    };

    let mut modules: Vec<BunModule> = Vec::with_capacity(module_count);
    for i in 0..module_count {
        let record_offset: usize = i
            .checked_mul(MODULE_RECORD_LEN)
            .ok_or_else(|| Error::Decompression("bun module record offset overflow".to_owned()))?;
        let rec: usize = table_start
            .checked_add(record_offset)
            .ok_or_else(|| Error::Decompression("bun module record offset overflow".to_owned()))?;
        let name_off: u32 = read_record_u32(bytes, rec, 0, "bun module name pointer truncated")?;
        let name_len: u32 = read_record_u32(bytes, rec, 4, "bun module name length truncated")?;
        let contents_offset: u32 =
            read_record_u32(bytes, rec, 8, "bun module contents offset truncated")?;
        let contents_length: u32 =
            read_record_u32(bytes, rec, 12, "bun module contents length truncated")?;
        let sourcemap_offset: u32 =
            read_record_u32(bytes, rec, 16, "bun module sourcemap offset truncated")?;
        let sourcemap_length: u32 =
            read_record_u32(bytes, rec, 20, "bun module sourcemap length truncated")?;
        let bytecode_length: u32 =
            read_record_u32(bytes, rec, 28, "bun module bytecode length truncated")?;
        let encoding: u8 = read_record_u8(bytes, rec, 48, "bun module encoding truncated")?;
        let loader: u8 = read_record_u8(bytes, rec, 49, "bun module loader truncated")?;
        let module_format: u8 = read_record_u8(bytes, rec, 50, "bun module format truncated")?;
        let name: String = resolve(name_off, name_len).map_or_else(
            || format!("module_{i}"),
            |s: &[u8]| String::from_utf8_lossy(s).into_owned(),
        );
        modules.push(BunModule {
            name,
            contents_offset,
            contents_length,
            sourcemap_offset,
            sourcemap_length,
            bytecode_length,
            encoding,
            loader,
            module_format,
            is_entry: i as u32 == offsets.entry_point_id,
        });
    }

    Ok(BunStandalone {
        trailer_offset: trailer as u64,
        data_start: data_start as u64,
        offsets,
        modules,
    })
}

pub fn module_contents<'a>(
    bytes: &'a [u8],
    archive: &BunStandalone,
    module: &BunModule,
) -> Option<&'a [u8]> {
    let start: usize =
        (archive.data_start as usize).checked_add(module.contents_offset as usize)?;
    let end: usize = start.checked_add(module.contents_length as usize)?;
    bytes.get(start..end)
}

pub fn sanitize_bun_name(name: &str) -> String {
    let trimmed: &str = name
        .trim_start_matches("/$bunfs/root/")
        .trim_start_matches("$bunfs/root/")
        .trim_start_matches("/$bunfs/")
        .trim_start_matches("$bunfs/");
    trimmed.trim_start_matches(['/', '\\']).to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn put_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn put_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    fn build_bun(modules: &[(&str, &[u8])]) -> Vec<u8> {
        let mut data: Vec<u8> = Vec::new();
        let mut name_ptrs: Vec<(u32, u32)> = Vec::new();
        let mut content_ptrs: Vec<(u32, u32)> = Vec::new();
        for (name, body) in modules {
            let name_off: u32 = data.len() as u32;
            data.extend_from_slice(name.as_bytes());
            name_ptrs.push((name_off, name.len() as u32));
            let body_off: u32 = data.len() as u32;
            data.extend_from_slice(body);
            content_ptrs.push((body_off, body.len() as u32));
        }
        let byte_count: u64 = data.len() as u64;
        let modules_offset: u32 = byte_count as u32;
        let mut table: Vec<u8> = Vec::new();
        for i in 0..modules.len() {
            let (n_off, n_len): (u32, u32) = name_ptrs[i];
            let (c_off, c_len): (u32, u32) = content_ptrs[i];
            put_u32(&mut table, n_off);
            put_u32(&mut table, n_len);
            put_u32(&mut table, c_off);
            put_u32(&mut table, c_len);
            put_u32(&mut table, 0);
            put_u32(&mut table, 0);
            put_u32(&mut table, 0);
            put_u32(&mut table, 0);
            table.extend_from_slice(&[0u8; 16]);
            table.push(2);
            table.push(1);
            table.push(1);
            table.push(0);
        }
        let modules_length: u32 = table.len() as u32;

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        out.extend(std::iter::repeat_n(0u8, 60));
        out.extend_from_slice(&data);
        out.extend_from_slice(&table);
        put_u64(&mut out, byte_count);
        put_u32(&mut out, modules_offset);
        put_u32(&mut out, modules_length);
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        put_u32(&mut out, 0);
        out.extend_from_slice(BUN_TRAILER);
        out
    }

    #[test]
    fn detects_and_carves_bun_modules() {
        let bytes: Vec<u8> = build_bun(&[
            ("/$bunfs/root/index.js", b"console.log('entry')"),
            ("/$bunfs/root/util.js", b"export const x = 42;"),
        ]);
        assert!(detect_bun(&bytes).is_some());
        let archive: BunStandalone = parse_bun(&bytes).expect("parse bun");
        assert_eq!(archive.modules.len(), 2);
        assert!(archive.modules[0].is_entry);
        assert_eq!(sanitize_bun_name(&archive.modules[0].name), "index.js");
        let body: &[u8] = module_contents(&bytes, &archive, &archive.modules[0]).expect("contents");
        assert_eq!(body, b"console.log('entry')");
        let body2: &[u8] =
            module_contents(&bytes, &archive, &archive.modules[1]).expect("contents");
        assert_eq!(body2, b"export const x = 42;");
    }

    #[test]
    fn rejects_non_bun_binary() {
        let mut bytes: Vec<u8> = vec![0x7f, b'E', b'L', b'F'];
        bytes.extend(std::iter::repeat_n(0u8, 1024));
        assert!(detect_bun(&bytes).is_none());
    }

    #[test]
    fn rejects_incoherent_module_table_offset() {
        let mut bytes: Vec<u8> = build_bun(&[("a.js", b"x")]);
        let trailer: usize = find_trailer(&bytes).expect("trailer");
        let offsets_base: usize = trailer.checked_sub(OFFSETS_LEN).expect("offsets");
        bytes[offsets_base + 8..offsets_base + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(detect_bun(&bytes).is_none());
        assert!(parse_bun(&bytes).is_err());
    }

    #[test]
    fn truncated_trailer_does_not_panic() {
        let full: Vec<u8> = build_bun(&[("a.js", b"x")]);
        for cut in (64..full.len()).step_by(5) {
            let _ = parse_bun(&full[..cut]);
        }
    }
}
