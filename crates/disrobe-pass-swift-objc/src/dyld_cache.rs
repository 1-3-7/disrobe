use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::macho::{
    self, Bitness, Endian, LC_SEGMENT, LC_SEGMENT_64, LoadCommand, ParsedSlice, Segment,
    read_cstr_bounded, u32_le, u64_le,
};

const MAGIC_PREFIX: &[u8] = b"dyld_v1";
const MAGIC_LEN: usize = 16;

const MAPPING_OFFSET_FIELD: usize = 0x10;
const MAPPING_COUNT_FIELD: usize = 0x14;
const IMAGES_OFFSET_OLD_FIELD: usize = 0x18;
const IMAGES_COUNT_OLD_FIELD: usize = 0x1C;
const IMAGES_OFFSET_NEW_FIELD: usize = 0x1C0;
const IMAGES_COUNT_NEW_FIELD: usize = 0x1C4;
const IMAGES_NEW_FIELDS_END: usize = 0x1C8;

const MAPPING_INFO_SIZE: usize = 32;
const IMAGE_INFO_SIZE: usize = 32;

const MAX_MAPPINGS: usize = 4096;
const MAX_IMAGES: usize = 1 << 20;
const MAX_IMAGE_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TOTAL_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;

const SEG64_FILEOFF_FIELD: usize = 40;
const SEG32_FILEOFF_FIELD: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldMapping {
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub max_prot: u32,
    pub init_prot: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldImage {
    pub address: u64,
    pub install_name: String,
    pub path_file_offset: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DyldSharedCache {
    pub magic: String,
    pub arch: String,
    pub endian: Endian,
    pub mapping_offset: u32,
    pub mapping_count: u32,
    pub images_offset: u32,
    pub images_count: u32,
    pub mappings: Vec<DyldMapping>,
    pub images: Vec<DyldImage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructedDylib {
    pub install_name: String,
    pub image_address: u64,
    pub header_file_offset: usize,
    pub segment_count: usize,
    pub bytes: Vec<u8>,
}

#[must_use]
pub fn is_dyld_shared_cache(bytes: &[u8]) -> bool {
    bytes
        .get(0..MAGIC_LEN)
        .is_some_and(|magic: &[u8]| magic.starts_with(MAGIC_PREFIX))
}

pub fn parse(cache: &[u8]) -> Result<DyldSharedCache> {
    let magic_bytes: &[u8] = cache.get(0..MAGIC_LEN).ok_or(Error::NotDyldCache)?;
    if !magic_bytes.starts_with(MAGIC_PREFIX) {
        return Err(Error::NotDyldCache);
    }
    let nul: usize = magic_bytes
        .iter()
        .position(|b: &u8| *b == 0)
        .unwrap_or(MAGIC_LEN);
    let magic: String = String::from_utf8_lossy(&magic_bytes[..nul])
        .trim()
        .to_owned();
    let arch: String = magic
        .strip_prefix("dyld_v1")
        .map_or("", str::trim)
        .to_owned();

    let mapping_offset: u32 = u32_le(cache, MAPPING_OFFSET_FIELD)?;
    let mapping_count: u32 = u32_le(cache, MAPPING_COUNT_FIELD)?;
    let images_offset_old: u32 = u32_le(cache, IMAGES_OFFSET_OLD_FIELD)?;
    let images_count_old: u32 = u32_le(cache, IMAGES_COUNT_OLD_FIELD)?;

    let (images_offset, images_count): (u32, u32) =
        if images_count_old != 0 && images_offset_old != 0 {
            (images_offset_old, images_count_old)
        } else if (mapping_offset as usize) >= IMAGES_NEW_FIELDS_END {
            (
                u32_le(cache, IMAGES_OFFSET_NEW_FIELD)?,
                u32_le(cache, IMAGES_COUNT_NEW_FIELD)?,
            )
        } else {
            return Err(Error::BadDyldCache(
            "legacy image fields are zero and the header is too small for the relocated image list"
                .to_owned(),
        ));
        };

    let mapping_count_usize: usize = mapping_count as usize;
    if mapping_count_usize > MAX_MAPPINGS {
        return Err(Error::BadDyldCache(format!(
            "mapping count {mapping_count} exceeds the {MAX_MAPPINGS} mapping cap"
        )));
    }
    let images_count_usize: usize = images_count as usize;
    if images_count_usize > MAX_IMAGES {
        return Err(Error::BadDyldCache(format!(
            "image count {images_count} exceeds the {MAX_IMAGES} image cap"
        )));
    }

    let mappings: Vec<DyldMapping> = parse_mappings(cache, mapping_offset, mapping_count_usize)?;
    let images: Vec<DyldImage> = parse_images(cache, images_offset, images_count_usize)?;

    Ok(DyldSharedCache {
        magic,
        arch,
        endian: Endian::Little,
        mapping_offset,
        mapping_count,
        images_offset,
        images_count,
        mappings,
        images,
    })
}

fn table_bounds(
    base: u32,
    count: usize,
    entry: usize,
    cache_len: usize,
    what: &str,
) -> Result<usize> {
    let start: usize = base as usize;
    let span: usize = count
        .checked_mul(entry)
        .ok_or_else(|| Error::BadDyldCache(format!("{what} table size overflows")))?;
    let end: usize = start
        .checked_add(span)
        .ok_or_else(|| Error::BadDyldCache(format!("{what} table end overflows")))?;
    if end > cache_len {
        return Err(Error::BadDyldCache(format!(
            "{what} table [{start}, {end}) exceeds cache length {cache_len}"
        )));
    }
    Ok(start)
}

fn parse_mappings(cache: &[u8], offset: u32, count: usize) -> Result<Vec<DyldMapping>> {
    let base: usize = table_bounds(offset, count, MAPPING_INFO_SIZE, cache.len(), "mapping")?;
    let mut out: Vec<DyldMapping> = Vec::with_capacity(count);
    for i in 0..count {
        let off: usize = base + i * MAPPING_INFO_SIZE;
        let address: u64 = u64_le(cache, off)?;
        let size: u64 = u64_le(cache, off + 8)?;
        let file_offset: u64 = u64_le(cache, off + 16)?;
        let max_prot: u32 = u32_le(cache, off + 24)?;
        let init_prot: u32 = u32_le(cache, off + 28)?;
        out.push(DyldMapping {
            address,
            size,
            file_offset,
            max_prot,
            init_prot,
        });
    }
    Ok(out)
}

fn parse_images(cache: &[u8], offset: u32, count: usize) -> Result<Vec<DyldImage>> {
    let base: usize = table_bounds(offset, count, IMAGE_INFO_SIZE, cache.len(), "image")?;
    let mut out: Vec<DyldImage> = Vec::with_capacity(count);
    for i in 0..count {
        let off: usize = base + i * IMAGE_INFO_SIZE;
        let address: u64 = u64_le(cache, off)?;
        let path_file_offset: u32 = u32_le(cache, off + 24)?;
        let install_name: String = read_cstr_bounded(cache, path_file_offset as usize, cache.len())
            .ok_or_else(|| {
                Error::BadDyldCache(format!(
                    "image {i} install-name at file offset {path_file_offset} is unreadable"
                ))
            })?;
        out.push(DyldImage {
            address,
            install_name,
            path_file_offset,
        });
    }
    Ok(out)
}

fn map_vmaddr(mappings: &[DyldMapping], vmaddr: u64) -> Option<usize> {
    for m in mappings {
        let Some(end): Option<u64> = m.address.checked_add(m.size) else {
            continue;
        };
        if vmaddr >= m.address && vmaddr < end {
            let delta: u64 = vmaddr - m.address;
            let file_off: u64 = m.file_offset.checked_add(delta)?;
            return usize::try_from(file_off).ok();
        }
    }
    None
}

pub fn reconstruct_image(
    cache: &[u8],
    parsed: &DyldSharedCache,
    index: usize,
) -> Result<ReconstructedDylib> {
    let image: &DyldImage = parsed.images.get(index).ok_or_else(|| {
        Error::BadDyldCache(format!(
            "image index {index} out of range ({} images)",
            parsed.images.len()
        ))
    })?;
    reconstruct(cache, parsed, image)
}

pub fn reconstruct_by_name(
    cache: &[u8],
    parsed: &DyldSharedCache,
    install_name: &str,
) -> Result<ReconstructedDylib> {
    let image: &DyldImage = parsed
        .images
        .iter()
        .find(|img: &&DyldImage| img.install_name == install_name)
        .ok_or_else(|| Error::BadDyldCache(format!("no bundled image named '{install_name}'")))?;
    reconstruct(cache, parsed, image)
}

pub fn reconstruct_all(cache: &[u8], parsed: &DyldSharedCache) -> Result<Vec<ReconstructedDylib>> {
    let mut out: Vec<ReconstructedDylib> = Vec::with_capacity(parsed.images.len());
    let mut total: u64 = 0;
    for image in &parsed.images {
        let dylib: ReconstructedDylib = reconstruct(cache, parsed, image)?;
        total = total
            .checked_add(dylib.bytes.len() as u64)
            .ok_or_else(|| Error::BadDyldCache("cumulative output size overflows".to_owned()))?;
        if total > MAX_TOTAL_OUTPUT_BYTES {
            return Err(Error::BadDyldCache(format!(
                "cumulative reconstructed output exceeds the {MAX_TOTAL_OUTPUT_BYTES}-byte cap"
            )));
        }
        out.push(dylib);
    }
    Ok(out)
}

fn reconstruct(
    cache: &[u8],
    parsed: &DyldSharedCache,
    image: &DyldImage,
) -> Result<ReconstructedDylib> {
    let header_off: usize = map_vmaddr(&parsed.mappings, image.address).ok_or_else(|| {
        Error::BadDyldCache(format!(
            "image '{}' address {:#x} is not covered by any mapping",
            image.install_name, image.address
        ))
    })?;
    let remainder: &[u8] = cache
        .get(header_off..)
        .ok_or(Error::Truncated(header_off))?;
    if macho::detect_magic(remainder).is_none() {
        return Err(Error::NotMachO);
    }
    let macho: ParsedSlice = macho::parse_slice(remainder)?;

    let is_64: bool = matches!(macho.header.bitness, Bitness::Bits64);
    let fileoff_field: usize = if is_64 {
        SEG64_FILEOFF_FIELD
    } else {
        SEG32_FILEOFF_FIELD
    };
    let field_len: usize = if is_64 { 8 } else { 4 };

    let seg_lcs: Vec<&LoadCommand> = macho
        .load_commands
        .iter()
        .filter(|lc: &&LoadCommand| lc.cmd == LC_SEGMENT_64 || lc.cmd == LC_SEGMENT)
        .collect();
    if seg_lcs.len() != macho.segments.len() {
        return Err(Error::BadDyldCache(
            "segment load-command count does not match parsed segment count".to_owned(),
        ));
    }

    let mut output: Vec<u8> = Vec::new();
    let mut patches: Vec<(usize, u64)> = Vec::with_capacity(macho.segments.len());
    let mut running: u64 = 0;

    for (seg, lc) in macho.segments.iter().zip(seg_lcs.iter()) {
        let new_fileoff: u64 = copy_segment(cache, &parsed.mappings, seg, running, &mut output)?;
        if seg.filesize != 0 {
            running = running
                .checked_add(seg.filesize)
                .ok_or_else(|| Error::BadDyldCache("segment layout size overflows".to_owned()))?;
            if running > MAX_IMAGE_OUTPUT_BYTES {
                return Err(Error::BadDyldCache(format!(
                    "reconstructed image exceeds the {MAX_IMAGE_OUTPUT_BYTES}-byte cap"
                )));
            }
        }
        let patch_at: usize = lc.data_offset.checked_add(fileoff_field).ok_or_else(|| {
            Error::BadDyldCache("segment fileoff field offset overflows".to_owned())
        })?;
        patches.push((patch_at, new_fileoff));
    }

    for (patch_at, new_fileoff) in patches {
        let end: usize = patch_at
            .checked_add(field_len)
            .ok_or_else(|| Error::BadDyldCache("segment fileoff field end overflows".to_owned()))?;
        let field: &mut [u8] = output.get_mut(patch_at..end).ok_or_else(|| {
            Error::BadDyldCache(
                "segment fileoff field falls outside the reconstructed header segment".to_owned(),
            )
        })?;
        if is_64 {
            field.copy_from_slice(&new_fileoff.to_le_bytes());
        } else {
            let narrowed: u32 = u32::try_from(new_fileoff).map_err(|_| {
                Error::BadDyldCache("32-bit segment fileoff exceeds u32 range".to_owned())
            })?;
            field.copy_from_slice(&narrowed.to_le_bytes());
        }
    }

    let reparsed: ParsedSlice = macho::parse_slice(&output)?;
    if reparsed.segments.len() != macho.segments.len() {
        return Err(Error::BadDyldCache(
            "reconstructed image segment count does not round-trip".to_owned(),
        ));
    }

    Ok(ReconstructedDylib {
        install_name: image.install_name.clone(),
        image_address: image.address,
        header_file_offset: header_off,
        segment_count: macho.segments.len(),
        bytes: output,
    })
}

fn copy_segment(
    cache: &[u8],
    mappings: &[DyldMapping],
    seg: &Segment,
    running: u64,
    output: &mut Vec<u8>,
) -> Result<u64> {
    if seg.filesize == 0 {
        return Ok(0);
    }
    let seg_off: usize = map_vmaddr(mappings, seg.vmaddr).ok_or_else(|| {
        Error::BadDyldCache(format!(
            "segment '{}' vmaddr {:#x} is not covered by any mapping",
            seg.name, seg.vmaddr
        ))
    })?;
    let size: usize = usize::try_from(seg.filesize)
        .map_err(|_| Error::BadDyldCache("segment filesize is not addressable".to_owned()))?;
    let end: usize = seg_off
        .checked_add(size)
        .ok_or_else(|| Error::BadDyldCache("segment file range overflows".to_owned()))?;
    let bytes: &[u8] = cache.get(seg_off..end).ok_or_else(|| {
        Error::BadDyldCache(format!(
            "segment '{}' range [{seg_off}, {end}) exceeds cache length {}",
            seg.name,
            cache.len()
        ))
    })?;
    output.extend_from_slice(bytes);
    Ok(running)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const MH_MAGIC_64: u32 = 0xFEED_FACF;
    const CPU_ARM64: u32 = 0x0100_000C;
    const CPU_SUB_ARM64_ALL: u32 = 0x0000_0000;
    const MH_DYLIB: u32 = 0x6;
    const LC_SEG_64: u32 = 0x19;

    const TEXT_VMADDR: u64 = 0x1_8000_0000;
    const DATA_VMADDR: u64 = 0x1_8000_4000;
    const LINKEDIT_VMADDR: u64 = 0x1_8000_8000;

    const TEXT_FILESIZE: u64 = 0x100;
    const DATA_FILESIZE: u64 = 0x40;
    const LINKEDIT_FILESIZE: u64 = 0x30;

    const MAP1_FILEOFF: u64 = 0x4000;
    const MAP2_FILEOFF: u64 = 0xC000;
    const MAP3_FILEOFF: u64 = 0x1_4000;

    const INSTALL_NAME: &str = "/usr/lib/libExample.dylib";

    fn seg_command(name: &str, vmaddr: u64, vmsize: u64, fileoff: u64, filesize: u64) -> Vec<u8> {
        let mut cmd: Vec<u8> = Vec::with_capacity(72);
        cmd.extend_from_slice(&LC_SEG_64.to_le_bytes());
        cmd.extend_from_slice(&72u32.to_le_bytes());
        let mut seg_name: [u8; 16] = [0u8; 16];
        let raw: &[u8] = name.as_bytes();
        seg_name[..raw.len()].copy_from_slice(raw);
        cmd.extend_from_slice(&seg_name);
        cmd.extend_from_slice(&vmaddr.to_le_bytes());
        cmd.extend_from_slice(&vmsize.to_le_bytes());
        cmd.extend_from_slice(&fileoff.to_le_bytes());
        cmd.extend_from_slice(&filesize.to_le_bytes());
        cmd.extend_from_slice(&7u32.to_le_bytes());
        cmd.extend_from_slice(&5u32.to_le_bytes());
        cmd.extend_from_slice(&0u32.to_le_bytes());
        cmd.extend_from_slice(&0u32.to_le_bytes());
        cmd
    }

    fn build_standalone_dylib() -> Vec<u8> {
        let text_cmd: Vec<u8> = seg_command("__TEXT", TEXT_VMADDR, TEXT_FILESIZE, 0, TEXT_FILESIZE);
        let data_cmd: Vec<u8> = seg_command(
            "__DATA",
            DATA_VMADDR,
            DATA_FILESIZE,
            TEXT_FILESIZE,
            DATA_FILESIZE,
        );
        let linkedit_cmd: Vec<u8> = seg_command(
            "__LINKEDIT",
            LINKEDIT_VMADDR,
            LINKEDIT_FILESIZE,
            TEXT_FILESIZE + DATA_FILESIZE,
            LINKEDIT_FILESIZE,
        );
        let sizeofcmds: u32 = (text_cmd.len() + data_cmd.len() + linkedit_cmd.len()) as u32;

        let mut header: Vec<u8> = Vec::with_capacity(32);
        header.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        header.extend_from_slice(&CPU_ARM64.to_le_bytes());
        header.extend_from_slice(&CPU_SUB_ARM64_ALL.to_le_bytes());
        header.extend_from_slice(&MH_DYLIB.to_le_bytes());
        header.extend_from_slice(&3u32.to_le_bytes());
        header.extend_from_slice(&sizeofcmds.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());
        header.extend_from_slice(&0u32.to_le_bytes());

        let mut dylib: Vec<u8> = Vec::new();
        dylib.extend_from_slice(&header);
        dylib.extend_from_slice(&text_cmd);
        dylib.extend_from_slice(&data_cmd);
        dylib.extend_from_slice(&linkedit_cmd);
        assert!(
            dylib.len() as u64 <= TEXT_FILESIZE,
            "load commands must fit __TEXT"
        );
        dylib.resize(TEXT_FILESIZE as usize, 0xCC);
        for i in 0..DATA_FILESIZE as usize {
            dylib.push((0x40 + (i & 0x0F)) as u8);
        }
        for i in 0..LINKEDIT_FILESIZE as usize {
            dylib.push((0x80 + (i & 0x0F)) as u8);
        }
        assert_eq!(
            dylib.len() as u64,
            TEXT_FILESIZE + DATA_FILESIZE + LINKEDIT_FILESIZE
        );
        dylib
    }

    fn write_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(buf: &mut [u8], off: usize, value: u64) {
        buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn build_cache(dylib: &[u8]) -> Vec<u8> {
        let mapping_offset: u32 = 0x100;
        let images_offset: u32 = 0x200;
        let name_offset: u32 = 0x240;
        let cache_len: usize = (MAP3_FILEOFF + LINKEDIT_FILESIZE) as usize;
        let mut cache: Vec<u8> = vec![0u8; cache_len];

        let mut magic: [u8; MAGIC_LEN] = [0u8; MAGIC_LEN];
        let magic_str: &[u8] = b"dyld_v1  arm64e";
        magic[..magic_str.len()].copy_from_slice(magic_str);
        cache[..MAGIC_LEN].copy_from_slice(&magic);

        write_u32(&mut cache, MAPPING_OFFSET_FIELD, mapping_offset);
        write_u32(&mut cache, MAPPING_COUNT_FIELD, 3);
        write_u32(&mut cache, IMAGES_OFFSET_OLD_FIELD, images_offset);
        write_u32(&mut cache, IMAGES_COUNT_OLD_FIELD, 1);

        let mapping_specs: [(u64, u64, u64); 3] = [
            (TEXT_VMADDR, 0x4000, MAP1_FILEOFF),
            (DATA_VMADDR, 0x4000, MAP2_FILEOFF),
            (LINKEDIT_VMADDR, 0x4000, MAP3_FILEOFF),
        ];
        for (i, (addr, size, fileoff)) in mapping_specs.iter().enumerate() {
            let off: usize = mapping_offset as usize + i * MAPPING_INFO_SIZE;
            write_u64(&mut cache, off, *addr);
            write_u64(&mut cache, off + 8, *size);
            write_u64(&mut cache, off + 16, *fileoff);
            write_u32(&mut cache, off + 24, 5);
            write_u32(&mut cache, off + 28, 5);
        }

        let img_off: usize = images_offset as usize;
        write_u64(&mut cache, img_off, TEXT_VMADDR);
        write_u64(&mut cache, img_off + 8, 0);
        write_u64(&mut cache, img_off + 16, 0);
        write_u32(&mut cache, img_off + 24, name_offset);
        write_u32(&mut cache, img_off + 28, 0);

        let name_bytes: &[u8] = INSTALL_NAME.as_bytes();
        let name_at: usize = name_offset as usize;
        cache[name_at..name_at + name_bytes.len()].copy_from_slice(name_bytes);

        let text: &[u8] = &dylib[..TEXT_FILESIZE as usize];
        let data: &[u8] = &dylib[TEXT_FILESIZE as usize..(TEXT_FILESIZE + DATA_FILESIZE) as usize];
        let linkedit: &[u8] = &dylib[(TEXT_FILESIZE + DATA_FILESIZE) as usize..];

        let mut cached_text: Vec<u8> = text.to_vec();
        write_u64(&mut cached_text, 32 + SEG64_FILEOFF_FIELD, MAP1_FILEOFF);
        write_u64(&mut cached_text, 104 + SEG64_FILEOFF_FIELD, MAP2_FILEOFF);
        write_u64(&mut cached_text, 176 + SEG64_FILEOFF_FIELD, MAP3_FILEOFF);

        let t: usize = MAP1_FILEOFF as usize;
        cache[t..t + cached_text.len()].copy_from_slice(&cached_text);
        let d: usize = MAP2_FILEOFF as usize;
        cache[d..d + data.len()].copy_from_slice(data);
        let l: usize = MAP3_FILEOFF as usize;
        cache[l..l + linkedit.len()].copy_from_slice(linkedit);

        cache
    }

    #[test]
    fn parses_header_mappings_and_images() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        assert!(is_dyld_shared_cache(&cache));
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        assert_eq!(parsed.arch, "arm64e");
        assert_eq!(parsed.mappings.len(), 3);
        assert_eq!(parsed.images.len(), 1);
        assert_eq!(parsed.images[0].address, TEXT_VMADDR);
        assert_eq!(parsed.images[0].install_name, INSTALL_NAME);
        assert_eq!(parsed.mappings[1].file_offset, MAP2_FILEOFF);
    }

    #[test]
    fn reconstructs_bundled_dylib_byte_for_byte() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        let recovered: ReconstructedDylib =
            reconstruct_image(&cache, &parsed, 0).expect("image reconstructs");
        assert_eq!(recovered.install_name, INSTALL_NAME);
        assert_eq!(recovered.image_address, TEXT_VMADDR);
        assert_eq!(recovered.header_file_offset, MAP1_FILEOFF as usize);
        assert_eq!(recovered.segment_count, 3);
        assert_eq!(recovered.bytes, dylib, "un-bundled dylib matches original");
        let reparsed: ParsedSlice =
            macho::parse_slice(&recovered.bytes).expect("recovered image parses via macho");
        assert_eq!(reparsed.segments.len(), 3);
        assert_eq!(reparsed.segments[0].name, "__TEXT");
        assert_eq!(reparsed.segments[0].fileoff, 0);
        assert_eq!(reparsed.segments[1].fileoff, TEXT_FILESIZE);
        assert_eq!(reparsed.segments[2].fileoff, TEXT_FILESIZE + DATA_FILESIZE);
    }

    #[test]
    fn reconstruct_by_name_matches_index() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        let by_name: ReconstructedDylib =
            reconstruct_by_name(&cache, &parsed, INSTALL_NAME).expect("named image reconstructs");
        assert_eq!(by_name.bytes, dylib);
    }

    #[test]
    fn reconstruct_all_respects_image_list() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let cache: Vec<u8> = build_cache(&dylib);
        let parsed: DyldSharedCache = parse(&cache).expect("cache parses");
        let all: Vec<ReconstructedDylib> =
            reconstruct_all(&cache, &parsed).expect("all images reconstruct");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].bytes, dylib);
    }

    #[test]
    fn rejects_wrong_magic() {
        let mut cache: Vec<u8> = vec![0u8; 64];
        cache[..4].copy_from_slice(b"PK\x03\x04");
        assert!(!is_dyld_shared_cache(&cache));
        assert!(matches!(parse(&cache), Err(Error::NotDyldCache)));
    }

    #[test]
    fn rejects_mapping_table_past_cache_length() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        write_u32(&mut cache, MAPPING_COUNT_FIELD, 100_000);
        assert!(matches!(parse(&cache), Err(Error::BadDyldCache(_))));
    }

    #[test]
    fn rejects_image_address_outside_mappings() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        let img_off: usize = 0x200;
        write_u64(&mut cache, img_off, 0x7F00_0000_0000);
        let parsed: DyldSharedCache = parse(&cache).expect("cache still parses");
        assert!(matches!(
            reconstruct_image(&cache, &parsed, 0),
            Err(Error::BadDyldCache(_))
        ));
    }

    #[test]
    fn rejects_mapping_count_over_cap() {
        let dylib: Vec<u8> = build_standalone_dylib();
        let mut cache: Vec<u8> = build_cache(&dylib);
        write_u32(&mut cache, MAPPING_COUNT_FIELD, (MAX_MAPPINGS + 1) as u32);
        assert!(matches!(parse(&cache), Err(Error::BadDyldCache(_))));
    }

    #[test]
    fn short_and_random_inputs_never_panic() {
        for len in 0usize..40 {
            let buf: Vec<u8> = vec![0x11u8; len];
            let _ = parse(&buf);
            let _ = is_dyld_shared_cache(&buf);
        }
        let mut crafted: Vec<u8> = vec![0u8; 0x40];
        crafted[..7].copy_from_slice(MAGIC_PREFIX);
        write_u32(&mut crafted, MAPPING_OFFSET_FIELD, u32::MAX);
        write_u32(&mut crafted, MAPPING_COUNT_FIELD, u32::MAX);
        write_u32(&mut crafted, IMAGES_OFFSET_OLD_FIELD, u32::MAX);
        write_u32(&mut crafted, IMAGES_COUNT_OLD_FIELD, u32::MAX);
        assert!(parse(&crafted).is_err());
    }
}
