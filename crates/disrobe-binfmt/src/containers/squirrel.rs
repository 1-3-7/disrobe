use object::LittleEndian as LE;
use object::read::pe::{
    DataDirectories, PeFile32, PeFile64, ResourceDirectory, ResourceNameOrId, SectionTable,
};
use serde::{Deserialize, Serialize};

use crate::container::find_subslice;

const PE_MAGIC: &[u8; 2] = b"MZ";
const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const CDFH_SIGNATURE: u32 = 0x0201_4b50;
const EOCD_FIXED_LEN: usize = 22;
const CDFH_FIXED_LEN: usize = 46;
const MAX_COMMENT: usize = 0xFFFF;
const SEARCH_BUDGET: usize = MAX_COMMENT + EOCD_FIXED_LEN + 4;
const MAX_CD_ENTRIES: usize = 1_000_000;

const SQUIRREL_MARKERS: [&[u8]; 3] = [b"SquirrelAwareVersion", b"Squirrel", b"NuGet"];
const SQUIRREL_RESOURCE_TYPE: &str = "DATA";
const SQUIRREL_RESOURCE_ID: u16 = 131;
const NUSPEC_SUFFIX: &str = ".nuspec";
const NUPKG_SUFFIX: &str = ".nupkg";
const CONTENT_TYPES_ENTRY: &str = "[Content_Types].xml";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SquirrelLayout {
    pub squirrel_marker_present: bool,
    pub nupkg_offset: Option<u64>,
    pub nupkg_size: Option<u64>,
    pub nupkg_entry_count: Option<u32>,
    pub nuspec_names: Vec<String>,
    pub package_names: Vec<String>,
}

#[must_use]
pub fn detect_squirrel(bytes: &[u8]) -> Option<SquirrelLayout> {
    if !bytes.starts_with(PE_MAGIC) {
        return None;
    }
    let marker_present: bool = SQUIRREL_MARKERS
        .iter()
        .any(|m: &&[u8]| find_subslice(bytes, m, 0).is_some());
    let embedded: Option<EmbeddedNupkg> = locate_embedded_nupkg(bytes);
    if !marker_present && embedded.is_none() {
        return None;
    }
    Some(match embedded {
        Some(found) => SquirrelLayout {
            squirrel_marker_present: marker_present,
            nupkg_offset: Some(found.zip_start as u64),
            nupkg_size: Some(found.zip_len as u64),
            nupkg_entry_count: Some(found.entry_count),
            nuspec_names: found.nuspec_names,
            package_names: found.package_names,
        },
        None => SquirrelLayout {
            squirrel_marker_present: marker_present,
            nupkg_offset: None,
            nupkg_size: None,
            nupkg_entry_count: None,
            nuspec_names: Vec::new(),
            package_names: Vec::new(),
        },
    })
}

#[derive(Debug)]
pub struct EmbeddedNupkg {
    pub zip_start: usize,
    pub zip_len: usize,
    pub entry_count: u32,
    pub nuspec_names: Vec<String>,
    pub package_names: Vec<String>,
}

#[must_use]
pub fn locate_embedded_nupkg(bytes: &[u8]) -> Option<EmbeddedNupkg> {
    let (resource_start, resource_len): (usize, usize) = squirrel_resource(bytes)?;
    let resource: &[u8] = bytes.get(resource_start..resource_start.checked_add(resource_len)?)?;
    let (eocd, total_entries): (usize, u16) = find_eocd(resource)?;
    let cd_start: usize = usize::try_from(read_u32(resource, eocd + 16)?).ok()?;
    let comment_len: usize = usize::from(read_u16(resource, eocd + 20)?);
    let names: Vec<String> = central_directory_names(resource, cd_start, eocd, total_entries);
    let nuspec_names: Vec<String> = names
        .iter()
        .filter(|name: &&String| name.ends_with(NUSPEC_SUFFIX))
        .cloned()
        .collect();
    let package_names: Vec<String> = names
        .iter()
        .filter(|name: &&String| name.ends_with(NUPKG_SUFFIX))
        .cloned()
        .collect();
    let is_nupkg: bool = !nuspec_names.is_empty()
        && names.iter().any(|name: &String| {
            name == CONTENT_TYPES_ENTRY || name.starts_with("lib/") || name.contains("/lib/")
        });
    if package_names.is_empty() && !is_nupkg {
        return None;
    }
    Some(EmbeddedNupkg {
        zip_start: resource_start,
        zip_len: eocd.checked_add(EOCD_FIXED_LEN)?.checked_add(comment_len)?,
        entry_count: u32::from(total_entries),
        nuspec_names,
        package_names,
    })
}

fn squirrel_resource(bytes: &[u8]) -> Option<(usize, usize)> {
    if let Ok(file) = PeFile32::parse(bytes) {
        return resource_in(bytes, &file.section_table(), file.data_directories());
    }
    let file: PeFile64<'_> = PeFile64::parse(bytes).ok()?;
    resource_in(bytes, &file.section_table(), file.data_directories())
}

fn resource_in<'data>(
    bytes: &'data [u8],
    sections: &SectionTable<'data>,
    directories: DataDirectories<'data>,
) -> Option<(usize, usize)> {
    let directory: ResourceDirectory<'data> =
        directories.resource_directory(bytes, sections).ok()??;
    for type_entry in directory.root().ok()?.entries {
        let ResourceNameOrId::Name(name) = type_entry.name_or_id() else {
            continue;
        };
        if name.to_string_lossy(directory).ok()?.as_str() != SQUIRREL_RESOURCE_TYPE {
            continue;
        }
        let Some(ids) = type_entry.data(directory).ok()?.table() else {
            continue;
        };
        for id_entry in ids.entries {
            if id_entry.name_or_id().id() != Some(SQUIRREL_RESOURCE_ID) {
                continue;
            }
            let Some(languages) = id_entry.data(directory).ok()?.table() else {
                continue;
            };
            for language in languages.entries {
                let Some(data) = language.data(directory).ok()?.data() else {
                    continue;
                };
                let (offset, available): (u32, u32) =
                    sections.pe_file_range_at(data.offset_to_data.get(LE))?;
                let size: u32 = data.size.get(LE);
                if size <= available {
                    return Some((usize::try_from(offset).ok()?, usize::try_from(size).ok()?));
                }
            }
        }
    }
    None
}

fn central_directory_names(
    zip: &[u8],
    cd_start: usize,
    cd_end: usize,
    total_entries: u16,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cursor: usize = cd_start;
    let mut seen: u16 = 0;
    while seen < total_entries && cursor + CDFH_FIXED_LEN <= cd_end {
        if read_u32(zip, cursor) != Some(CDFH_SIGNATURE) {
            break;
        }
        let name_len: usize = usize::from(read_u16(zip, cursor + 28).unwrap_or(0));
        let extra_len: usize = usize::from(read_u16(zip, cursor + 30).unwrap_or(0));
        let comment_len: usize = usize::from(read_u16(zip, cursor + 32).unwrap_or(0));
        let name_start: usize = cursor + CDFH_FIXED_LEN;
        let name_end: usize = name_start.saturating_add(name_len);
        if name_end > cd_end {
            break;
        }
        if let Ok(name) = std::str::from_utf8(&zip[name_start..name_end]) {
            names.push(name.replace('\\', "/"));
        }
        cursor = name_end
            .saturating_add(extra_len)
            .saturating_add(comment_len);
        seen += 1;
    }
    names
}

fn find_eocd(zip: &[u8]) -> Option<(usize, u16)> {
    let len: usize = zip.len();
    if len < EOCD_FIXED_LEN {
        return None;
    }
    let start: usize = len.saturating_sub(SEARCH_BUDGET);
    (start..=len - EOCD_FIXED_LEN).rev().find_map(|off: usize| {
        if read_u32(zip, off) != Some(EOCD_SIGNATURE) {
            return None;
        }
        let total_entries: u16 = read_u16(zip, off + 10)?;
        let cd_size: usize = usize::try_from(read_u32(zip, off + 12)?).ok()?;
        let cd_start: usize = usize::try_from(read_u32(zip, off + 16)?).ok()?;
        let comment_len: usize = usize::from(read_u16(zip, off + 20)?);
        let consistent: bool = total_entries > 0
            && usize::from(total_entries) <= MAX_CD_ENTRIES
            && cd_start.checked_add(cd_size) == Some(off)
            && read_u32(zip, cd_start) == Some(CDFH_SIGNATURE)
            && off + EOCD_FIXED_LEN + comment_len <= len;
        consistent.then_some((off, total_entries))
    })
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
    const PE_OFFSET: usize = 0x80;
    const HEADERS_SIZE: usize = 0x200;
    const SECTION_RVA: u32 = 0x1000;
    const ZIP_IN_SECTION: usize = 104;
    const RESOURCE_PADDING: usize = 16;

    fn put_u16(buf: &mut Vec<u8>, value: u16) {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    fn put_u32(buf: &mut Vec<u8>, value: u32) {
        buf.extend_from_slice(&value.to_le_bytes());
    }
    fn table(buf: &mut Vec<u8>, named: u16, ids: u16) {
        buf.extend(std::iter::repeat_n(0u8, 12));
        put_u16(buf, named);
        put_u16(buf, ids);
    }

    let resource_size: u32 = u32::try_from(nupkg_zip.len() + RESOURCE_PADDING).expect("size");
    let mut rsrc: Vec<u8> = Vec::new();
    table(&mut rsrc, 1, 0);
    put_u32(&mut rsrc, 0x8000_0000 | 0x58);
    put_u32(&mut rsrc, 0x8000_0000 | 0x18);
    table(&mut rsrc, 0, 1);
    put_u32(&mut rsrc, u32::from(SQUIRREL_RESOURCE_ID));
    put_u32(&mut rsrc, 0x8000_0000 | 0x30);
    table(&mut rsrc, 0, 1);
    put_u32(&mut rsrc, 1033);
    put_u32(&mut rsrc, 72);
    put_u32(&mut rsrc, SECTION_RVA + ZIP_IN_SECTION as u32);
    put_u32(&mut rsrc, resource_size);
    put_u32(&mut rsrc, 0);
    put_u32(&mut rsrc, 0);
    put_u16(&mut rsrc, 4);
    for unit in SQUIRREL_RESOURCE_TYPE.encode_utf16() {
        put_u16(&mut rsrc, unit);
    }
    rsrc.resize(ZIP_IN_SECTION, 0);
    rsrc.extend_from_slice(nupkg_zip);
    rsrc.extend(std::iter::repeat_n(0u8, RESOURCE_PADDING));
    let raw_size: usize = rsrc.len().next_multiple_of(0x200);
    rsrc.resize(raw_size, 0);
    let section_size: u32 = u32::try_from(raw_size).expect("section size");

    let mut out: Vec<u8> = Vec::with_capacity(HEADERS_SIZE + raw_size);
    out.extend_from_slice(PE_MAGIC);
    out.resize(0x3C, 0);
    put_u32(&mut out, PE_OFFSET as u32);
    out.extend_from_slice(b"SquirrelAwareVersion 1 NuGet Squirrel\0");
    out.resize(PE_OFFSET, 0);
    out.extend_from_slice(b"PE\0\0");
    put_u16(&mut out, 0x014C);
    put_u16(&mut out, 1);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u16(&mut out, 0xE0);
    put_u16(&mut out, 0x0102);
    let optional: usize = out.len();
    out.resize(optional + 0xE0, 0);
    out[optional..optional + 2].copy_from_slice(&0x010Bu16.to_le_bytes());
    out[optional + 28..optional + 32].copy_from_slice(&0x0040_0000u32.to_le_bytes());
    out[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    out[optional + 36..optional + 40].copy_from_slice(&0x200u32.to_le_bytes());
    out[optional + 56..optional + 60].copy_from_slice(&(SECTION_RVA + section_size).to_le_bytes());
    out[optional + 60..optional + 64].copy_from_slice(&(HEADERS_SIZE as u32).to_le_bytes());
    out[optional + 68..optional + 70].copy_from_slice(&2u16.to_le_bytes());
    out[optional + 92..optional + 96].copy_from_slice(&16u32.to_le_bytes());
    out[optional + 112..optional + 116].copy_from_slice(&SECTION_RVA.to_le_bytes());
    out[optional + 116..optional + 120].copy_from_slice(&section_size.to_le_bytes());
    out.extend_from_slice(b".rsrc\0\0\0");
    put_u32(&mut out, section_size);
    put_u32(&mut out, SECTION_RVA);
    put_u32(&mut out, section_size);
    put_u32(&mut out, HEADERS_SIZE as u32);
    put_u32(&mut out, 0);
    put_u32(&mut out, 0);
    put_u16(&mut out, 0);
    put_u16(&mut out, 0);
    put_u32(&mut out, 0x4000_0040);
    out.resize(HEADERS_SIZE, 0);
    out.extend_from_slice(&rsrc);
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
    fn a_setup_payload_resource_names_its_packages_and_ends_at_its_directory() {
        let payload: Vec<u8> = synth_nupkg(&[
            ("App-1.0.0-full.nupkg", b"PK\x03\x04 inner package"),
            ("RELEASES", b"0123 App-1.0.0-full.nupkg 20"),
            ("Update.exe", b"MZ update"),
        ]);
        let setup: Vec<u8> = build_test_squirrel_setup(&payload);
        let layout: SquirrelLayout = detect_squirrel(&setup).expect("squirrel detected");
        assert_eq!(
            layout.package_names,
            vec!["App-1.0.0-full.nupkg".to_owned()]
        );
        assert_eq!(layout.nupkg_entry_count, Some(3));
        let start: usize = usize::try_from(layout.nupkg_offset.expect("offset")).expect("offset");
        let size: usize = usize::try_from(layout.nupkg_size.expect("size")).expect("size");
        assert_eq!(&setup[start..start + size], payload.as_slice());
    }

    #[test]
    fn a_zip_appended_after_the_pe_is_not_the_setup_payload() {
        let payload: Vec<u8> = synth_nupkg(&[("App-1.0.0-full.nupkg", b"x")]);
        let mut bytes: Vec<u8> = build_test_squirrel_setup(&synth_nupkg(&[("readme", b"r")]));
        bytes.extend_from_slice(&payload);
        let layout: SquirrelLayout = detect_squirrel(&bytes).expect("marker present");
        assert!(layout.nupkg_offset.is_none(), "{layout:?}");
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
