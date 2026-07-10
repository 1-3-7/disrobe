use serde::{Deserialize, Serialize};

const PE_MAGIC: &[u8; 2] = b"MZ";
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CDFH_SIGNATURE: u32 = 0x0201_4b50;
const EOCD_FIXED_LEN: usize = 22;
const CDFH_FIXED_LEN: usize = 46;
const MAX_COMMENT: usize = 0xFFFF;
const SEARCH_BUDGET: usize = MAX_COMMENT + EOCD_FIXED_LEN + 4;
const MAX_CD_ENTRIES: usize = 1_000_000;

const SQUIRREL_MARKERS: [&[u8]; 3] = [b"SquirrelAwareVersion", b"Squirrel", b"NuGet"];
const NUSPEC_SUFFIX: &str = ".nuspec";
const CONTENT_TYPES_ENTRY: &str = "[Content_Types].xml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SquirrelLayout {
    pub squirrel_marker_present: bool,
    pub nupkg_offset: Option<u64>,
    pub nupkg_size: Option<u64>,
    pub nupkg_entry_count: Option<u32>,
    pub nuspec_names: Vec<String>,
}

#[must_use]
pub fn detect_squirrel(bytes: &[u8]) -> Option<SquirrelLayout> {
    if !bytes.starts_with(PE_MAGIC) {
        return None;
    }
    let marker_present: bool = SQUIRREL_MARKERS
        .iter()
        .any(|m: &&[u8]| find_subslice(bytes, m).is_some());
    let embedded: Option<EmbeddedNupkg> = locate_embedded_nupkg(bytes);
    if !marker_present && embedded.is_none() {
        return None;
    }
    match embedded {
        Some(found) => Some(SquirrelLayout {
            squirrel_marker_present: marker_present,
            nupkg_offset: Some(found.zip_start as u64),
            nupkg_size: Some((bytes.len() - found.zip_start) as u64),
            nupkg_entry_count: Some(found.entry_count),
            nuspec_names: found.nuspec_names,
        }),
        None => Some(SquirrelLayout {
            squirrel_marker_present: marker_present,
            nupkg_offset: None,
            nupkg_size: None,
            nupkg_entry_count: None,
            nuspec_names: Vec::new(),
        }),
    }
}

#[derive(Debug)]
pub struct EmbeddedNupkg {
    pub zip_start: usize,
    pub entry_count: u32,
    pub nuspec_names: Vec<String>,
}

#[must_use]
pub fn locate_embedded_nupkg(bytes: &[u8]) -> Option<EmbeddedNupkg> {
    let eocd: usize = find_eocd(bytes)?;
    let cd_size: u32 = read_u32(bytes, eocd + 12)?;
    let cd_offset_field: u32 = read_u32(bytes, eocd + 16)?;
    let total_entries: u16 = read_u16(bytes, eocd + 10)?;
    if total_entries as usize > MAX_CD_ENTRIES || total_entries == 0 {
        return None;
    }
    let cd_size_usize: usize = cd_size as usize;
    let cd_end: usize = eocd;
    let cd_start: usize = cd_end.checked_sub(cd_size_usize)?;
    if read_u32(bytes, cd_start)? != CDFH_SIGNATURE {
        return None;
    }
    let zip_start: usize = cd_start.checked_sub(cd_offset_field as usize)?;
    if !bytes.starts_with(PE_MAGIC) || zip_start == 0 {
        return None;
    }
    let (names, looks_like_nupkg): (Vec<String>, bool) =
        scan_central_directory(bytes, cd_start, cd_end, total_entries, zip_start);
    if !looks_like_nupkg {
        return None;
    }
    Some(EmbeddedNupkg {
        zip_start,
        entry_count: u32::from(total_entries),
        nuspec_names: names,
    })
}

fn scan_central_directory(
    bytes: &[u8],
    cd_start: usize,
    cd_end: usize,
    total_entries: u16,
    zip_start: usize,
) -> (Vec<String>, bool) {
    let mut nuspec_names: Vec<String> = Vec::new();
    let mut saw_content_types: bool = false;
    let mut saw_lib: bool = false;
    let mut cursor: usize = cd_start;
    let mut seen: u16 = 0;
    while seen < total_entries && cursor + CDFH_FIXED_LEN <= cd_end {
        if read_u32(bytes, cursor) != Some(CDFH_SIGNATURE) {
            break;
        }
        let name_len: usize =
            usize::from(read_u16(bytes, cursor + 28).map_or(0, |value: u16| value));
        let extra_len: usize =
            usize::from(read_u16(bytes, cursor + 30).map_or(0, |value: u16| value));
        let comment_len: usize =
            usize::from(read_u16(bytes, cursor + 32).map_or(0, |value: u16| value));
        let local_offset: u32 = read_u32(bytes, cursor + 42).map_or(u32::MAX, |value: u32| value);
        let name_start: usize = cursor + CDFH_FIXED_LEN;
        let name_end: usize = name_start.saturating_add(name_len);
        if name_end > cd_end {
            break;
        }
        if zip_start.checked_add(local_offset as usize).is_none() {
            break;
        }
        if let Ok(name) = std::str::from_utf8(&bytes[name_start..name_end]) {
            let normalized: String = name.replace('\\', "/");
            if normalized.ends_with(NUSPEC_SUFFIX) {
                nuspec_names.push(normalized.clone());
            }
            if normalized == CONTENT_TYPES_ENTRY {
                saw_content_types = true;
            }
            if normalized.starts_with("lib/") || normalized.contains("/lib/") {
                saw_lib = true;
            }
        }
        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
        seen += 1;
    }
    let looks_like_nupkg: bool = !nuspec_names.is_empty() && (saw_content_types || saw_lib);
    (nuspec_names, looks_like_nupkg)
}

fn find_eocd(bytes: &[u8]) -> Option<usize> {
    let len: usize = bytes.len();
    if len < EOCD_FIXED_LEN {
        return None;
    }
    let start: usize = len.saturating_sub(SEARCH_BUDGET);
    for off in (start..=len - EOCD_FIXED_LEN).rev() {
        if read_u32(bytes, off) == Some(EOCD_SIGNATURE) {
            let comment_len: usize =
                usize::from(read_u16(bytes, off + 20).map_or(0, |value: u16| value));
            if off + EOCD_FIXED_LEN + comment_len == len {
                return Some(off);
            }
        }
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let first: u8 = needle[0];
    let mut from: usize = 0;
    while let Some(rel) = haystack[from..].iter().position(|&b: &u8| b == first) {
        let at: usize = from + rel;
        if haystack[at..].starts_with(needle) {
            return Some(at);
        }
        from = at + 1;
    }
    None
}

#[inline]
fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    disrobe_bytes::read_u32_le_at(bytes, at).ok()
}

#[inline]
fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    disrobe_bytes::read_u16_le_at(bytes, at).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
pub(crate) fn build_test_squirrel_setup(nupkg_zip: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(2048 + nupkg_zip.len());
    out.extend_from_slice(PE_MAGIC);
    out.extend(std::iter::repeat_n(0u8, 510));
    out.extend_from_slice(b"this stub is SquirrelAwareVersion 1 built by NuGet Squirrel\0");
    out.extend(std::iter::repeat_n(0u8, 64));
    out.extend_from_slice(nupkg_zip);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::Cursor;
    use std::io::Write as _;

    use super::*;

    fn synth_nupkg(files: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        let mut zw: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        for (name, body) in files {
            zw.start_file(*name, opts).expect("start");
            zw.write_all(body).expect("write");
        }
        zw.finish().expect("finish").into_inner()
    }

    #[test]
    fn detects_embedded_nupkg_in_setup_stub() {
        let nupkg: Vec<u8> = synth_nupkg(&[
            ("Discord.nuspec", b"<package/>"),
            ("[Content_Types].xml", b"<Types/>"),
            ("lib/net45/Discord.exe", b"MZ\x90\x00 app"),
        ]);
        let stub: Vec<u8> = build_test_squirrel_setup(&nupkg);
        let layout: SquirrelLayout = detect_squirrel(&stub).expect("squirrel detected");
        assert!(layout.squirrel_marker_present);
        assert_eq!(layout.nupkg_entry_count, Some(3));
        assert!(layout.nupkg_offset.is_some());
        assert_eq!(layout.nuspec_names, vec!["Discord.nuspec".to_owned()]);
    }

    #[test]
    fn rejects_plain_pe_without_marker_or_nupkg() {
        let mut bytes: Vec<u8> = PE_MAGIC.to_vec();
        bytes.extend(std::iter::repeat_n(0u8, 4096));
        assert!(detect_squirrel(&bytes).is_none());
    }

    #[test]
    fn rejects_non_pe() {
        let bytes: Vec<u8> = vec![0u8; 4096];
        assert!(detect_squirrel(&bytes).is_none());
    }

    #[test]
    fn marker_present_but_no_embedded_zip() {
        let mut bytes: Vec<u8> = PE_MAGIC.to_vec();
        bytes.extend_from_slice(b" SquirrelAwareVersion ");
        bytes.extend(std::iter::repeat_n(0u8, 4096));
        let layout: SquirrelLayout = detect_squirrel(&bytes).expect("marker present");
        assert!(layout.squirrel_marker_present);
        assert!(layout.nupkg_offset.is_none());
    }

    #[test]
    fn appended_zip_without_nuspec_is_not_nupkg() {
        let plain_zip: Vec<u8> = synth_nupkg(&[("readme.txt", b"hello")]);
        let stub: Vec<u8> = build_test_squirrel_setup(&plain_zip);
        let layout: SquirrelLayout = detect_squirrel(&stub).expect("marker present");
        assert!(layout.squirrel_marker_present);
        assert!(layout.nupkg_offset.is_none());
    }
}
