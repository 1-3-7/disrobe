use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::binary::{Endian, GoImage};
use crate::debug::{dbg_kv, dbg_line, dbg_section};
use crate::pclntab::{LocatedPclntab, PclntabVersion};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Moduledata {
    pub pclntab_va: u64,
    pub typelinks_va: u64,
    pub typelinks_len: u64,
    pub itablinks_va: u64,
    pub itablinks_len: u64,
    pub types_va: u64,
    pub etypes_va: u64,
    pub text_va: u64,
    pub etext_va: u64,
    pub modulename: Option<String>,
    pub buildversion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_info: Option<GoBuildInfo>,
    pub via: ModuledataSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuledataSource {
    SymbolRuntimeFirstmoduledata,
    PclntabBacksearch,
    None,
}

const RUNTIME_FIRSTMODULE_SYM: &str = "runtime.firstmoduledata";

const MAX_BACKSEARCH_CANDIDATES: usize = 4096;

#[must_use]
pub fn locate_moduledata(image: &GoImage<'_>, located: &LocatedPclntab<'_>) -> Moduledata {
    dbg_section("go.moduledata");
    let build_info: Option<GoBuildInfo> = extract_build_info(image);
    let modulename: Option<String> = extract_modulename(image);
    dbg_kv("modulename", || format!("{modulename:?}"));
    dbg_kv("build_info_deps", || {
        build_info
            .as_ref()
            .map_or(0, |b: &GoBuildInfo| b.deps.len())
            .to_string()
    });
    dbg_kv("build_info_settings", || {
        build_info
            .as_ref()
            .map_or(0, |b: &GoBuildInfo| b.settings.len())
            .to_string()
    });
    let version: PclntabVersion = located.header.version;
    let go_version: Option<String> = build_info
        .as_ref()
        .and_then(|b: &GoBuildInfo| b.go_version.clone())
        .or_else(|| extract_buildversion(image));
    dbg_kv("moduledata_layout_version", || version.label().to_owned());
    if let Some(mut md) = via_symbol(image, version, go_version.as_deref()) {
        dbg_line(|| {
            format!(
                "moduledata via runtime.firstmoduledata symbol: text={:#x}..{:#x} types={:#x}",
                md.text_va, md.etext_va, md.types_va
            )
        });
        md.modulename = modulename;
        md.build_info = build_info;
        return md;
    }
    if let Some(mut md) = via_pclntab_backsearch(image, located, version, go_version.as_deref()) {
        dbg_line(|| {
            format!(
                "moduledata via pclntab back-search: text={:#x}..{:#x} types={:#x}",
                md.text_va, md.etext_va, md.types_va
            )
        });
        md.modulename = modulename;
        md.build_info = build_info;
        return md;
    }
    dbg_line(|| {
        format!(
            "moduledata not located by symbol or back-search; pclntab_va={:#x}",
            located.header.section_addr
        )
    });
    Moduledata {
        pclntab_va: located.header.section_addr,
        typelinks_va: 0,
        typelinks_len: 0,
        itablinks_va: 0,
        itablinks_len: 0,
        types_va: 0,
        etypes_va: 0,
        text_va: located.header.text_start,
        etext_va: 0,
        modulename,
        buildversion: extract_buildversion(image),
        build_info,
        via: ModuledataSource::None,
    }
}

fn via_symbol(
    image: &GoImage<'_>,
    version: PclntabVersion,
    go_version: Option<&str>,
) -> Option<Moduledata> {
    let entry: &(String, u64, u64) = image
        .symbol_addrs
        .iter()
        .find(|(n, _, _)| n == RUNTIME_FIRSTMODULE_SYM)?;
    let va: u64 = entry.1;
    walk_moduledata(
        image,
        va,
        ModuledataSource::SymbolRuntimeFirstmoduledata,
        version,
        go_version,
    )
}

fn via_pclntab_backsearch(
    image: &GoImage<'_>,
    located: &LocatedPclntab<'_>,
    version: PclntabVersion,
    go_version: Option<&str>,
) -> Option<Moduledata> {
    let pclntab_va: u64 = located.header.section_addr;
    let ps: u8 = image.ptr_size;
    let mut attempts: usize = 0;
    for sec in &image.sections {
        if sec.data.is_empty() {
            continue;
        }
        let step: usize = ps as usize;
        let mut off: usize = 0;
        while off + step <= sec.data.len() {
            let val: u64 = match (ps, image.endian) {
                (4, Endian::Little) => <[u8; 4]>::try_from(&sec.data[off..off + 4])
                    .map_or(0, |a: [u8; 4]| u64::from(u32::from_le_bytes(a))),
                (4, Endian::Big) => <[u8; 4]>::try_from(&sec.data[off..off + 4])
                    .map_or(0, |a: [u8; 4]| u64::from(u32::from_be_bytes(a))),
                (8, Endian::Little) => {
                    <[u8; 8]>::try_from(&sec.data[off..off + 8]).map_or(0, u64::from_le_bytes)
                }
                (8, Endian::Big) => {
                    <[u8; 8]>::try_from(&sec.data[off..off + 8]).map_or(0, u64::from_be_bytes)
                }
                _ => 0,
            };
            if val == pclntab_va {
                if attempts >= MAX_BACKSEARCH_CANDIDATES {
                    return None;
                }
                attempts += 1;
                let Some(candidate_va): Option<u64> = u64::try_from(off)
                    .ok()
                    .and_then(|delta: u64| sec.address.checked_add(delta))
                else {
                    off += step;
                    continue;
                };
                if let Some(md) = walk_moduledata(
                    image,
                    candidate_va,
                    ModuledataSource::PclntabBacksearch,
                    version,
                    go_version,
                ) {
                    return Some(md);
                }
            }
            off += step;
        }
    }
    None
}

const MD_WORD_TEXT: u64 = 22;
const MD_WORD_ETEXT: u64 = 23;

const MAX_PLAUSIBLE_SLICE_LEN: u64 = 1 << 22;

#[derive(Debug, Clone, Copy)]
enum Epclntab {
    Absent,
    Present,
    Unresolved,
}

#[derive(Debug, Clone, Copy)]
struct MdLayout {
    types_word: u64,
    typelinks_base_word: u64,
    epclntab: Epclntab,
}

fn md_layout(magic_version: PclntabVersion, go_version: Option<&str>) -> MdLayout {
    build_minor(go_version)
        .and_then(layout_from_minor)
        .unwrap_or_else(|| layout_from_magic(magic_version))
}

const fn layout_from_minor(minor: u32) -> Option<MdLayout> {
    let layout: MdLayout = match minor {
        16 | 17 => MdLayout {
            types_word: 35,
            typelinks_base_word: 40,
            epclntab: Epclntab::Absent,
        },
        18 | 19 => MdLayout {
            types_word: 35,
            typelinks_base_word: 42,
            epclntab: Epclntab::Absent,
        },
        20..=25 => MdLayout {
            types_word: 37,
            typelinks_base_word: 44,
            epclntab: Epclntab::Absent,
        },
        _ if minor >= 26 => MdLayout {
            types_word: 37,
            typelinks_base_word: 44,
            epclntab: Epclntab::Present,
        },
        _ => return None,
    };
    Some(layout)
}

const fn layout_from_magic(magic_version: PclntabVersion) -> MdLayout {
    match magic_version {
        PclntabVersion::Go116 => MdLayout {
            types_word: 35,
            typelinks_base_word: 40,
            epclntab: Epclntab::Absent,
        },
        PclntabVersion::Go118 => MdLayout {
            types_word: 35,
            typelinks_base_word: 42,
            epclntab: Epclntab::Absent,
        },
        PclntabVersion::Go12 | PclntabVersion::Go120 => MdLayout {
            types_word: 37,
            typelinks_base_word: 44,
            epclntab: Epclntab::Unresolved,
        },
    }
}

const TL_VALIDATE_SAMPLE: u64 = 64;
const TL_MIN_VALID_PCT: u64 = 75;

fn score_typelinks_word(
    image: &GoImage<'_>,
    base: u64,
    ps: u64,
    tl_word: u64,
    types_blob_len: u64,
) -> Option<u64> {
    if types_blob_len == 0 {
        return None;
    }
    let raw_ptr: u64 = read_module_word(image, base, ps, tl_word)?;
    let raw_len: u64 = read_module_word(image, base, ps, tl_word.checked_add(1)?)?;
    let (ptr, len): (u64, u64) = validated_slice(image, raw_ptr, raw_len, 4);
    if ptr == 0 || len == 0 {
        return None;
    }
    let sample: u64 = len.min(TL_VALIDATE_SAMPLE);
    let mut read: u64 = 0;
    let mut in_range: u64 = 0;
    for i in 0..sample {
        let Some(entry_va): Option<u64> = i.checked_mul(4).and_then(|d: u64| ptr.checked_add(d))
        else {
            break;
        };
        let Some(off): Option<u32> = image.read_u32(entry_va) else {
            break;
        };
        read += 1;
        if u64::from(off) < types_blob_len {
            in_range += 1;
        }
    }
    if read == 0 {
        return None;
    }
    Some(in_range.saturating_mul(100) / read)
}

fn build_minor(go_version: Option<&str>) -> Option<u32> {
    let rest: &str = go_version?.strip_prefix("go1.")?;
    let dot: usize = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..dot)?.parse().ok()
}

fn resolve_typelinks_word(
    image: &GoImage<'_>,
    base: u64,
    ps: u64,
    layout: MdLayout,
    types_va: u64,
    etypes_va: u64,
) -> u64 {
    let tl_base: u64 = layout.typelinks_base_word;
    match layout.epclntab {
        Epclntab::Absent => tl_base,
        Epclntab::Present => tl_base + 1,
        Epclntab::Unresolved => {
            let blob_len: u64 = etypes_va.saturating_sub(types_va);
            let s0: Option<u64> = score_typelinks_word(image, base, ps, tl_base, blob_len);
            let s1: Option<u64> = score_typelinks_word(image, base, ps, tl_base + 1, blob_len);
            match (s0, s1) {
                (Some(a), Some(b)) if b > a && b >= TL_MIN_VALID_PCT => tl_base + 1,
                (Some(a), _) if a >= TL_MIN_VALID_PCT => tl_base,
                (None, Some(b)) if b >= TL_MIN_VALID_PCT => tl_base + 1,
                _ => tl_base,
            }
        }
    }
}

fn walk_moduledata(
    image: &GoImage<'_>,
    base: u64,
    via: ModuledataSource,
    version: PclntabVersion,
    go_version: Option<&str>,
) -> Option<Moduledata> {
    let ps: u64 = u64::from(image.ptr_size);
    let word = |index: u64| -> Option<u64> { read_module_word(image, base, ps, index) };
    let pclntab_va: u64 = image.read_ptr(base)?;
    let text_va: u64 = word(MD_WORD_TEXT)?;
    let etext_va: u64 = word(MD_WORD_ETEXT)?;
    let layout: MdLayout = md_layout(version, go_version);
    let types_va: u64 = word(layout.types_word)?;
    let etypes_va: u64 = word(layout.types_word + 1)?;
    let tl_word: u64 = resolve_typelinks_word(image, base, ps, layout, types_va, etypes_va);
    let (typelinks_va, typelinks_len): (u64, u64) = validated_slice(
        image,
        word(tl_word).unwrap_or(0),
        word(tl_word + 1).unwrap_or(0),
        4,
    );
    let (itablinks_va, itablinks_len): (u64, u64) = validated_slice(
        image,
        word(tl_word + 3).unwrap_or(0),
        word(tl_word + 4).unwrap_or(0),
        ps,
    );
    Some(Moduledata {
        pclntab_va,
        typelinks_va,
        typelinks_len,
        itablinks_va,
        itablinks_len,
        types_va,
        etypes_va,
        text_va,
        etext_va,
        modulename: None,
        buildversion: extract_buildversion(image),
        build_info: None,
        via,
    })
}

fn read_module_word(image: &GoImage<'_>, base: u64, ptr_size: u64, index: u64) -> Option<u64> {
    let delta: u64 = ptr_size.checked_mul(index)?;
    let va: u64 = base.checked_add(delta)?;
    image.read_ptr(va)
}

fn validated_slice(image: &GoImage<'_>, ptr: u64, len: u64, elem_size: u64) -> (u64, u64) {
    if ptr == 0 || len == 0 || elem_size == 0 || len > MAX_PLAUSIBLE_SLICE_LEN {
        return (0, 0);
    }
    let Some(span): Option<u64> = len.checked_mul(elem_size) else {
        return (0, 0);
    };
    let Some(last_va): Option<u64> = span
        .checked_sub(1)
        .and_then(|last: u64| ptr.checked_add(last))
    else {
        return (0, 0);
    };
    if image.data_at_va(ptr, 1).is_none() || image.data_at_va(last_va, 1).is_none() {
        return (0, 0);
    }
    (ptr, len)
}

const BUILDINFO_MARKER: &[u8] = b"\xff Go buildinf:";
const BUILDINFO_HEADER_LEN: usize = 32;
const BUILDINFO_FLAG_OFFSET: usize = 15;
const BUILDINFO_PTRSIZE_OFFSET: usize = 14;
const BUILDINFO_FLAG_INLINE_STRINGS: u8 = 0x2;
const BUILDINFO_ALIGNMENT: u64 = 16;
const BUILDINFO_SENTINEL_LEN: usize = 16;
const BUILDINFO_MAX_STRING_LEN: u64 = 1 << 20;
const MAX_MODULENAME_LEN: usize = 4096;

#[must_use]
pub fn extract_modulename(image: &GoImage<'_>) -> Option<String> {
    let info: GoBuildInfo = extract_build_info(image)?;
    let candidate: String = info
        .main
        .as_ref()
        .map(|m: &GoModule| m.path.clone())
        .or(info.path)?;
    if candidate.is_empty() || candidate == "command-line-arguments" {
        return None;
    }
    Some(candidate)
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GoModule {
    pub path: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sum: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace: Option<Box<Self>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct GoBuildInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub go_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main: Option<GoModule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deps: Vec<GoModule>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub settings: BTreeMap<String, String>,
}

const SETTING_GOOS: &str = "GOOS";
const SETTING_GOARCH: &str = "GOARCH";
const SETTING_COMPILER: &str = "-compiler";
const SETTING_BUILDMODE: &str = "-buildmode";
const SETTING_CGO: &str = "CGO_ENABLED";
const SETTING_VCS: &str = "vcs";
const SETTING_VCS_REVISION: &str = "vcs.revision";
const SETTING_VCS_TIME: &str = "vcs.time";
const SETTING_VCS_MODIFIED: &str = "vcs.modified";

impl GoBuildInfo {
    #[must_use]
    pub fn setting(&self, key: &str) -> Option<&str> {
        self.settings.get(key).map(String::as_str)
    }

    #[must_use]
    pub fn goos(&self) -> Option<&str> {
        self.setting(SETTING_GOOS)
    }

    #[must_use]
    pub fn goarch(&self) -> Option<&str> {
        self.setting(SETTING_GOARCH)
    }

    #[must_use]
    pub fn compiler(&self) -> Option<&str> {
        self.setting(SETTING_COMPILER)
    }

    #[must_use]
    pub fn buildmode(&self) -> Option<&str> {
        self.setting(SETTING_BUILDMODE)
    }

    #[must_use]
    pub fn cgo_enabled(&self) -> Option<bool> {
        Some(self.setting(SETTING_CGO)? == "1")
    }

    #[must_use]
    pub fn vcs(&self) -> Option<&str> {
        self.setting(SETTING_VCS)
    }

    #[must_use]
    pub fn vcs_revision(&self) -> Option<&str> {
        self.setting(SETTING_VCS_REVISION)
    }

    #[must_use]
    pub fn vcs_time(&self) -> Option<&str> {
        self.setting(SETTING_VCS_TIME)
    }

    #[must_use]
    pub fn vcs_modified(&self) -> Option<bool> {
        Some(self.setting(SETTING_VCS_MODIFIED)? == "true")
    }
}

#[must_use]
pub fn extract_build_info(image: &GoImage<'_>) -> Option<GoBuildInfo> {
    for sec in &image.sections {
        let mut search_start: usize = 0;
        while let Some(haystack) = sec.data.get(search_start..) {
            let Some(relative): Option<usize> = find_subslice(haystack, BUILDINFO_MARKER) else {
                break;
            };
            let Some(marker_pos): Option<usize> = search_start.checked_add(relative) else {
                break;
            };
            let marker_offset: Option<u64> = u64::try_from(marker_pos).ok();
            let aligned: bool = marker_offset
                .and_then(|offset: u64| sec.address.checked_add(offset))
                .is_some_and(|address: u64| address.is_multiple_of(BUILDINFO_ALIGNMENT));
            if aligned
                && let Some(info) = decode_build_info(image, sec.data, marker_pos)
                && info.go_version.is_some()
            {
                return Some(info);
            }
            let Some(next_start): Option<usize> = marker_pos.checked_add(1) else {
                break;
            };
            search_start = next_start;
        }
    }
    None
}

fn decode_build_info(image: &GoImage<'_>, data: &[u8], marker_pos: usize) -> Option<GoBuildInfo> {
    let header: &[u8] = data.get(marker_pos..marker_pos + BUILDINFO_HEADER_LEN)?;
    let flags: u8 = header[BUILDINFO_FLAG_OFFSET];
    let ptr_size: u8 = header[BUILDINFO_PTRSIZE_OFFSET];
    if flags & BUILDINFO_FLAG_INLINE_STRINGS == 0 {
        return decode_build_info_pointer_form(image, header, ptr_size);
    }
    let body_start: usize = marker_pos + BUILDINFO_HEADER_LEN;
    let (go_version, after_vers): (&[u8], usize) = read_uvarint_string(data, body_start)?;
    let (mod_info, _): (&[u8], usize) = read_uvarint_string(data, after_vers)?;
    Some(build_info_from_parts(go_version, mod_info))
}

fn decode_build_info_pointer_form(
    image: &GoImage<'_>,
    header: &[u8],
    ptr_size: u8,
) -> Option<GoBuildInfo> {
    if !matches!(ptr_size, 4 | 8) {
        return None;
    }
    let width: usize = ptr_size as usize;
    let big_endian: bool = matches!(image.endian, crate::binary::Endian::Big);
    let vers_addr: u64 = read_addr(header.get(16..16 + width)?, big_endian)?;
    let mod_addr: u64 = read_addr(header.get(16 + width..16 + 2 * width)?, big_endian)?;
    let go_version: Vec<u8> = read_go_string(image, vers_addr)?;
    let mod_info: Vec<u8> = read_go_string(image, mod_addr)?;
    Some(build_info_from_parts(&go_version, &mod_info))
}

fn read_go_string(image: &GoImage<'_>, header_va: u64) -> Option<Vec<u8>> {
    let data_va: u64 = image.read_ptr(header_va)?;
    let len_va: u64 = header_va.checked_add(u64::from(image.ptr_size))?;
    let len: u64 = image.read_ptr(len_va)?;
    if len == 0 || len > BUILDINFO_MAX_STRING_LEN {
        return None;
    }
    let body: &[u8] = image.data_at_va(data_va, usize::try_from(len).ok()?)?;
    Some(body.to_vec())
}

fn read_addr(buf: &[u8], big_endian: bool) -> Option<u64> {
    if buf.len() >= 8 {
        let arr: [u8; 8] = buf.get(..8)?.try_into().ok()?;
        Some(if big_endian {
            u64::from_be_bytes(arr)
        } else {
            u64::from_le_bytes(arr)
        })
    } else {
        let arr: [u8; 4] = buf.get(..4)?.try_into().ok()?;
        Some(u64::from(if big_endian {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        }))
    }
}

const MAX_BUILDINFO_DEPS: usize = 1 << 16;
const MAX_BUILDINFO_SETTINGS: usize = 1 << 12;

enum LastModule {
    None,
    Main,
    Dep(usize),
}

fn build_info_from_parts(go_version: &[u8], mod_info: &[u8]) -> GoBuildInfo {
    let stripped: &[u8] = strip_build_info_sentinels(mod_info);
    let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(stripped);
    let mut info: GoBuildInfo = GoBuildInfo {
        go_version: bounded_owned(&String::from_utf8_lossy(go_version)),
        ..GoBuildInfo::default()
    };
    let mut last: LastModule = LastModule::None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("path\t") {
            if info.path.is_none() {
                info.path = bounded_owned(rest);
            }
        } else if let Some(rest) = line.strip_prefix("mod\t") {
            if let Some(module) = parse_module_line(rest) {
                info.main = Some(module);
                last = LastModule::Main;
            }
        } else if let Some(rest) = line.strip_prefix("dep\t") {
            if info.deps.len() < MAX_BUILDINFO_DEPS
                && let Some(module) = parse_module_line(rest)
            {
                info.deps.push(module);
                last = LastModule::Dep(info.deps.len() - 1);
            }
        } else if let Some(rest) = line.strip_prefix("=>\t") {
            if let Some(replacement) = parse_module_line(rest) {
                let target: Option<&mut GoModule> = match last {
                    LastModule::Main => info.main.as_mut(),
                    LastModule::Dep(idx) => info.deps.get_mut(idx),
                    LastModule::None => None,
                };
                if let Some(module) = target {
                    module.replace = Some(Box::new(replacement));
                }
            }
            last = LastModule::None;
        } else if let Some(rest) = line.strip_prefix("build\t")
            && info.settings.len() < MAX_BUILDINFO_SETTINGS
            && let Some((key, value)) = parse_build_setting(rest)
        {
            info.settings.entry(key).or_insert(value);
        }
    }
    info
}

fn parse_module_line(rest: &str) -> Option<GoModule> {
    let mut cols = rest.split('\t');
    let path: &str = cols.next()?;
    let bounded_path: String = bounded_owned(path)?;
    let version: String = cols.next().map(str::to_owned).unwrap_or_default();
    let sum: String = cols.next().map(str::to_owned).unwrap_or_default();
    Some(GoModule {
        path: bounded_path,
        version,
        sum,
        replace: None,
    })
}

fn parse_build_setting(kv: &str) -> Option<(String, String)> {
    let first: u8 = *kv.as_bytes().first()?;
    let (key, raw_value): (String, &str) = match first {
        b'=' => return None,
        b'`' | b'"' => {
            let (quoted, rest): (&str, &str) = quoted_prefix(kv)?;
            let after: &str = rest.strip_prefix('=')?;
            (unquote(quoted)?, after)
        }
        _ => {
            let (k, v): (&str, &str) = kv.split_once('=')?;
            (k.to_owned(), v)
        }
    };
    let value: String = match raw_value.as_bytes().first() {
        Some(b'`' | b'"') => {
            let (quoted, _): (&str, &str) = quoted_prefix(raw_value)?;
            unquote(quoted)?
        }
        _ => raw_value.to_owned(),
    };
    if key.is_empty()
        || key.len() > MAX_MODULENAME_LEN
        || value.len() > BUILDINFO_MAX_STRING_LEN as usize
    {
        return None;
    }
    Some((key, value))
}

fn quoted_prefix(s: &str) -> Option<(&str, &str)> {
    let bytes: &[u8] = s.as_bytes();
    let quote: u8 = *bytes.first()?;
    match quote {
        b'`' => {
            let end_rel: usize = bytes[1..].iter().position(|b: &u8| *b == b'`')?;
            let end: usize = 1 + end_rel + 1;
            Some((&s[..end], &s[end..]))
        }
        b'"' => {
            let mut i: usize = 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'"' => return Some((&s[..=i], &s[i + 1..])),
                    _ => i += 1,
                }
            }
            None
        }
        _ => None,
    }
}

fn unquote(s: &str) -> Option<String> {
    let bytes: &[u8] = s.as_bytes();
    let quote: u8 = *bytes.first()?;
    if bytes.len() < 2 || *bytes.last()? != quote {
        return None;
    }
    let inner: &[u8] = &bytes[1..bytes.len() - 1];
    if quote == b'`' {
        return Some(String::from_utf8_lossy(inner).into_owned());
    }
    let mut out: Vec<u8> = Vec::with_capacity(inner.len());
    let mut i: usize = 0;
    while i < inner.len() {
        let b: u8 = inner[i];
        if b != b'\\' {
            out.push(b);
            i += 1;
            continue;
        }
        i += 1;
        let esc: u8 = *inner.get(i)?;
        i += 1;
        match esc {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            b'\\' => out.push(b'\\'),
            b'\'' => out.push(b'\''),
            b'"' => out.push(b'"'),
            b'x' => out.push(u8::try_from(take_hex(inner, &mut i, 2)?).ok()?),
            b'u' => push_rune(&mut out, take_hex(inner, &mut i, 4)?)?,
            b'U' => push_rune(&mut out, take_hex(inner, &mut i, 8)?)?,
            b'0'..=b'7' => {
                let d1: u32 = octal_digit(*inner.get(i)?)?;
                let d2: u32 = octal_digit(*inner.get(i + 1)?)?;
                i += 2;
                let value: u32 = u32::from(esc - b'0') * 64 + d1 * 8 + d2;
                out.push(u8::try_from(value).ok()?);
            }
            _ => return None,
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

fn take_hex(inner: &[u8], i: &mut usize, count: usize) -> Option<u32> {
    let mut value: u32 = 0;
    for _ in 0..count {
        value = value * 16 + hex_digit(*inner.get(*i)?)?;
        *i += 1;
    }
    Some(value)
}

fn hex_digit(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'9' => Some(u32::from(b - b'0')),
        b'a'..=b'f' => Some(u32::from(b - b'a' + 10)),
        b'A'..=b'F' => Some(u32::from(b - b'A' + 10)),
        _ => None,
    }
}

fn octal_digit(b: u8) -> Option<u32> {
    match b {
        b'0'..=b'7' => Some(u32::from(b - b'0')),
        _ => None,
    }
}

fn push_rune(out: &mut Vec<u8>, cp: u32) -> Option<()> {
    let c: char = char::from_u32(cp)?;
    let mut buf: [u8; 4] = [0; 4];
    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    Some(())
}

fn bounded_owned(value: &str) -> Option<String> {
    let trimmed: &str = value.trim();
    if trimmed.is_empty() || trimmed.len() > MAX_MODULENAME_LEN {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn strip_build_info_sentinels(mod_info: &[u8]) -> &[u8] {
    if mod_info.len() >= 2 * BUILDINFO_SENTINEL_LEN {
        &mod_info[BUILDINFO_SENTINEL_LEN..mod_info.len() - BUILDINFO_SENTINEL_LEN]
    } else {
        mod_info
    }
}

fn read_uvarint_string(data: &[u8], at: usize) -> Option<(&[u8], usize)> {
    let (len, consumed): (u64, usize) = read_uvarint(data.get(at..)?)?;
    if len > BUILDINFO_MAX_STRING_LEN {
        return None;
    }
    let start: usize = at + consumed;
    let end: usize = start.checked_add(usize::try_from(len).ok()?)?;
    let body: &[u8] = data.get(start..end)?;
    Some((body, end))
}

fn read_uvarint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in buf.iter().take(10).enumerate() {
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
    }
    None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

#[must_use]
pub fn extract_buildversion(image: &GoImage<'_>) -> Option<String> {
    for sec in &image.sections {
        let needle: &[u8] = b"go1.";
        let mut i: usize = 0;
        while i + needle.len() <= sec.data.len() {
            if &sec.data[i..i + needle.len()] == needle {
                let tail: &[u8] = &sec.data[i..];
                let limit: usize = tail.len().min(32);
                let end: usize = tail
                    .iter()
                    .position(|b: &u8| !(b.is_ascii_alphanumeric() || *b == b'.' || *b == b'-'))
                    .unwrap_or(limit);
                if (4..=24).contains(&end)
                    && let Ok(s) = std::str::from_utf8(&tail[..end])
                    && s.chars().filter(|c: &char| *c == '.').count() >= 1
                {
                    return Some(s.to_owned());
                }
            }
            i += 1;
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::binary::{Endian, ImageKind, Section};

    #[test]
    fn uvarint_decodes_single_and_multi_byte() {
        assert_eq!(read_uvarint(&[0x08]), Some((8, 1)));
        assert_eq!(read_uvarint(&[0xd2, 0x02]), Some((0x152, 2)));
        assert_eq!(read_uvarint(&[]), None);
        assert_eq!(read_uvarint(&[0x80; 10]), None);
    }

    #[test]
    fn sentinel_strip_removes_16_byte_frames() {
        let inner: &[u8] = b"path\tembedfix\n";
        let mut framed: Vec<u8> = vec![0xaa; BUILDINFO_SENTINEL_LEN];
        framed.extend_from_slice(inner);
        framed.extend_from_slice(&[0xbb; BUILDINFO_SENTINEL_LEN]);
        assert_eq!(strip_build_info_sentinels(&framed), inner);
        assert_eq!(strip_build_info_sentinels(b"short"), b"short");
    }

    fn framed(inner: &[u8]) -> Vec<u8> {
        let mut blob: Vec<u8> = vec![0x00; BUILDINFO_SENTINEL_LEN];
        blob.extend_from_slice(inner);
        blob.extend_from_slice(&[0x00; BUILDINFO_SENTINEL_LEN]);
        blob
    }

    #[test]
    fn modinfo_tsv_extracts_path_and_mod() {
        let blob: Vec<u8> =
            framed(b"path\tembedfix\nmod\tembedfix\t(devel)\t\nbuild\t-trimpath=true\n");
        let info: GoBuildInfo = build_info_from_parts(b"go1.26.3", &blob);
        assert_eq!(info.path.as_deref(), Some("embedfix"));
        let main: &GoModule = info.main.as_ref().expect("main module");
        assert_eq!(main.path, "embedfix");
        assert_eq!(main.version, "(devel)");
        assert_eq!(info.go_version.as_deref(), Some("go1.26.3"));
        assert_eq!(info.setting("-trimpath"), Some("true"));
    }

    #[test]
    fn modinfo_main_module_keeps_version_and_hash() {
        let blob: Vec<u8> =
            framed(b"path\texample.com/cmd/app\nmod\texample.com/app\tv1.2.3\th1:abc=\n");
        let info: GoBuildInfo = build_info_from_parts(b"go1.26.3", &blob);
        assert_eq!(info.path.as_deref(), Some("example.com/cmd/app"));
        let main: &GoModule = info.main.as_ref().expect("main module");
        assert_eq!(main.path, "example.com/app");
        assert_eq!(main.version, "v1.2.3");
        assert_eq!(main.sum, "h1:abc=");
    }

    #[test]
    fn modinfo_collects_deps_and_replace_directive() {
        let blob: Vec<u8> = framed(
            b"path\texample.com/app\n\
              mod\texample.com/app\t(devel)\t\n\
              dep\tgithub.com/pkg/errors\tv0.9.1\th1:err=\n\
              dep\tgolang.org/x/sys\tv0.1.0\th1:sys=\n\
              =>\t../local/sys\tv0.0.0\th1:local=\n",
        );
        let info: GoBuildInfo = build_info_from_parts(b"go1.26.3", &blob);
        assert_eq!(info.deps.len(), 2);
        assert_eq!(info.deps[0].path, "github.com/pkg/errors");
        assert_eq!(info.deps[0].version, "v0.9.1");
        assert_eq!(info.deps[1].path, "golang.org/x/sys");
        let replace: &GoModule = info.deps[1]
            .replace
            .as_deref()
            .expect("replace directive on second dep");
        assert_eq!(replace.path, "../local/sys");
        assert_eq!(replace.sum, "h1:local=");
    }

    #[test]
    fn modinfo_surfaces_vcs_and_target_settings() {
        let blob: Vec<u8> = framed(
            b"path\tembedfix\nmod\tembedfix\t(devel)\t\n\
              build\t-buildmode=exe\nbuild\t-compiler=gc\n\
              build\tCGO_ENABLED=0\nbuild\tGOARCH=amd64\nbuild\tGOOS=windows\n\
              build\tvcs=git\nbuild\tvcs.revision=00ef2ac700625f78f4c43209b36305bfc86405cf\n\
              build\tvcs.time=2026-06-13T08:48:49Z\nbuild\tvcs.modified=true\n",
        );
        let info: GoBuildInfo = build_info_from_parts(b"go1.26.3", &blob);
        assert_eq!(info.goos(), Some("windows"));
        assert_eq!(info.goarch(), Some("amd64"));
        assert_eq!(info.compiler(), Some("gc"));
        assert_eq!(info.buildmode(), Some("exe"));
        assert_eq!(info.cgo_enabled(), Some(false));
        assert_eq!(info.vcs(), Some("git"));
        assert_eq!(
            info.vcs_revision(),
            Some("00ef2ac700625f78f4c43209b36305bfc86405cf")
        );
        assert_eq!(info.vcs_time(), Some("2026-06-13T08:48:49Z"));
        assert_eq!(info.vcs_modified(), Some(true));
    }

    #[test]
    fn build_setting_handles_quoted_value_with_tab() {
        assert_eq!(
            parse_build_setting("CGO_CFLAGS=\"-O2\\t-g\""),
            Some(("CGO_CFLAGS".to_owned(), "-O2\t-g".to_owned()))
        );
        assert_eq!(
            parse_build_setting("GOARCH=amd64"),
            Some(("GOARCH".to_owned(), "amd64".to_owned()))
        );
        assert_eq!(parse_build_setting("=novalue"), None);
        assert_eq!(parse_build_setting("nokey"), None);
    }

    #[test]
    fn unquote_decodes_full_go_escape_set() {
        assert_eq!(
            unquote("\"col1\\tcol2\\vcol3\"").as_deref(),
            Some("col1\tcol2\u{0b}col3")
        );
        assert_eq!(unquote("\"a b\\x00c\"").as_deref(), Some("a b\u{00}c"));
        assert_eq!(
            unquote("\"ring\\a bell\"").as_deref(),
            Some("ring\u{07} bell")
        );
        assert_eq!(unquote("\"e\\x1b[0m x\"").as_deref(), Some("e\u{1b}[0m x"));
        assert_eq!(
            unquote("\"tab\\tform\\ffeed\"").as_deref(),
            Some("tab\tform\u{0c}feed")
        );
        assert_eq!(
            unquote("\"back\\bspace\"").as_deref(),
            Some("back\u{08}space")
        );
        assert_eq!(
            unquote("\"snow\\u2603 man\"").as_deref(),
            Some("snow\u{2603} man")
        );
        assert_eq!(
            unquote("\"grin\\U0001F600face\"").as_deref(),
            Some("grin\u{1f600}face")
        );
        assert_eq!(unquote("\"nul\\000end\"").as_deref(), Some("nul\u{00}end"));
        assert_eq!(unquote("\"esc\\033seq\"").as_deref(), Some("esc\u{1b}seq"));
        assert_eq!(unquote("`raw\\tstays`").as_deref(), Some("raw\\tstays"));
        assert_eq!(unquote("\"bad\\q\""), None);
        assert_eq!(unquote("\"trunc\\x1\""), None);
    }

    #[cfg(not(miri))]
    #[test]
    fn unquote_inverts_go_strconv_quote() {
        let go: std::path::PathBuf = match std::env::var_os("PATH").and_then(|_| which_go()) {
            Some(p) => p,
            None => return,
        };
        let values: [&str; 8] = [
            "col1\tcol2\u{0b}col3",
            "a b\u{00}c",
            "ring\u{07} bell",
            "e\u{1b}[0m x",
            "tab\tform\u{0c}feed",
            "snow\u{2603} man\tx",
            "grin\u{1f600}face\tx",
            "back\u{08} space\"end",
        ];
        for value in values {
            let quoted: String = go_strconv_quote(&go, value);
            assert_eq!(
                unquote(&quoted).as_deref(),
                Some(value),
                "unquote must invert strconv.Quote for {value:?} (quoted {quoted:?})"
            );
        }
    }

    #[cfg(not(miri))]
    fn which_go() -> Option<std::path::PathBuf> {
        let out: std::process::Output = std::process::Command::new("go")
            .arg("version")
            .output()
            .ok()?;
        out.status.success().then(|| std::path::PathBuf::from("go"))
    }

    #[cfg(not(miri))]
    fn go_strconv_quote(go: &std::path::Path, value: &str) -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let unique: u64 = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe_go_quote_{}_{unique}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let src: &str = "package main\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"strconv\"\n)\nfunc main() {\n\tb, _ := os.ReadFile(os.Args[1])\n\tfmt.Print(strconv.Quote(string(b)))\n}\n";
        let src_path: std::path::PathBuf = dir.join("main.go");
        let in_path: std::path::PathBuf = dir.join("in.bin");
        std::fs::write(&src_path, src).unwrap();
        std::fs::write(&in_path, value.as_bytes()).unwrap();
        let out: std::process::Output = std::process::Command::new(go)
            .arg("run")
            .arg(&src_path)
            .arg(&in_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "go run failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let quoted: String = String::from_utf8(out.stdout).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        quoted
    }

    #[test]
    fn build_setting_handles_quoted_key() {
        assert_eq!(
            parse_build_setting("\"weird key\"=value"),
            Some(("weird key".to_owned(), "value".to_owned()))
        );
    }

    #[test]
    fn quoted_prefix_handles_raw_and_interpreted() {
        assert_eq!(quoted_prefix("`raw`rest"), Some(("`raw`", "rest")));
        assert_eq!(quoted_prefix("\"a\\\"b\"=x"), Some(("\"a\\\"b\"", "=x")));
        assert_eq!(quoted_prefix("unquoted"), None);
    }

    #[test]
    fn read_uvarint_string_bounds_checked() {
        let buf: &[u8] = &[0x03, b'a', b'b', b'c', b'x'];
        assert_eq!(read_uvarint_string(buf, 0), Some((b"abc".as_slice(), 4)));
        let truncated: &[u8] = &[0x09, b'a'];
        assert_eq!(read_uvarint_string(truncated, 0), None);
    }

    #[test]
    fn pointer_buildinfo_rejects_missing_string_body() {
        let base: u64 = 0x1000;
        let mut bytes: Vec<u8> = vec![0; 0x80];
        bytes[..BUILDINFO_MARKER.len()].copy_from_slice(BUILDINFO_MARKER);
        bytes[BUILDINFO_PTRSIZE_OFFSET] = 8;
        bytes[16..24].copy_from_slice(&(base + 0x40).to_le_bytes());
        bytes[24..32].copy_from_slice(&(base + 0x60).to_le_bytes());
        bytes[0x40..0x48].copy_from_slice(&(base + 0x70).to_le_bytes());
        bytes[0x48..0x50].copy_from_slice(&8u64.to_le_bytes());
        bytes[0x70..0x78].copy_from_slice(b"go1.26.3");
        bytes[0x60..0x68].copy_from_slice(&(base + 0x78).to_le_bytes());
        bytes[0x68..0x70].copy_from_slice(&9u64.to_le_bytes());
        let image: GoImage<'_> = GoImage {
            kind: ImageKind::Pe,
            endian: Endian::Little,
            ptr_size: 8,
            sections: vec![Section {
                name: ".rdata".to_owned(),
                address: base,
                data: &bytes,
            }],
            raw: &bytes,
            symbol_addrs: Vec::new(),
            flat: true,
        };
        assert_eq!(extract_build_info(&image), None);
    }

    fn write_inline_build_info(bytes: &mut [u8], offset: usize, version: &[u8]) {
        bytes[offset..offset + BUILDINFO_MARKER.len()].copy_from_slice(BUILDINFO_MARKER);
        bytes[offset + BUILDINFO_FLAG_OFFSET] = BUILDINFO_FLAG_INLINE_STRINGS;
        bytes[offset + BUILDINFO_HEADER_LEN] = u8::try_from(version.len()).unwrap();
        let version_start: usize = offset + BUILDINFO_HEADER_LEN + 1;
        bytes[version_start..version_start + version.len()].copy_from_slice(version);
        bytes[version_start + version.len()] = 0;
    }

    fn inline_build_info_image(bytes: &[u8]) -> GoImage<'_> {
        GoImage {
            kind: ImageKind::Pe,
            endian: Endian::Little,
            ptr_size: 8,
            sections: vec![Section {
                name: ".rdata".to_owned(),
                address: 0x1000,
                data: bytes,
            }],
            raw: bytes,
            symbol_addrs: Vec::new(),
            flat: true,
        }
    }

    #[test]
    fn buildinfo_skips_empty_inline_record_before_valid_record() {
        let mut bytes: Vec<u8> = vec![0; 0x100];
        write_inline_build_info(&mut bytes, 0, b"");
        write_inline_build_info(&mut bytes, 64, b"go1.26.3");
        let image: GoImage<'_> = inline_build_info_image(&bytes);
        let info: GoBuildInfo = extract_build_info(&image).expect("valid second build info");
        assert_eq!(info.go_version.as_deref(), Some("go1.26.3"));
    }

    #[test]
    fn buildinfo_skips_unaligned_record_before_valid_record() {
        let mut bytes: Vec<u8> = vec![0; 0x100];
        write_inline_build_info(&mut bytes, 1, b"go1.1.1");
        write_inline_build_info(&mut bytes, 64, b"go1.26.3");
        let image: GoImage<'_> = inline_build_info_image(&bytes);
        let info: GoBuildInfo = extract_build_info(&image).expect("valid aligned build info");
        assert_eq!(info.go_version.as_deref(), Some("go1.26.3"));
    }

    #[test]
    fn validated_slice_rejects_wrapped_end_address() {
        let low: [u8; 16] = [0u8; 16];
        let high: [u8; 32] = [0u8; 32];
        let image: GoImage<'_> = GoImage {
            kind: ImageKind::Pe,
            endian: Endian::Little,
            ptr_size: 8,
            sections: vec![
                Section {
                    name: ".low".to_owned(),
                    address: 0,
                    data: &low,
                },
                Section {
                    name: ".high".to_owned(),
                    address: u64::MAX - 32,
                    data: &high,
                },
            ],
            raw: &low,
            symbol_addrs: Vec::new(),
            flat: true,
        };
        assert_eq!(validated_slice(&image, u64::MAX - 20, 32, 1), (0, 0));
    }

    #[test]
    fn read_module_word_rejects_wrapped_word_address() {
        let low: [u8; 16] = [0xffu8; 16];
        let image: GoImage<'_> = GoImage {
            kind: ImageKind::Pe,
            endian: Endian::Little,
            ptr_size: 8,
            sections: vec![Section {
                name: ".low".to_owned(),
                address: 0,
                data: &low,
            }],
            raw: &low,
            symbol_addrs: Vec::new(),
            flat: true,
        };
        assert_eq!(read_module_word(&image, u64::MAX - 3, 8, 1), None);
    }

    #[test]
    fn walk_moduledata_rejects_truncated_mandatory_words() {
        let base: u64 = 0x1000;
        let mut bytes: Vec<u8> = vec![0u8; 16];
        bytes[..8].copy_from_slice(&(base + 0x80).to_le_bytes());
        let image: GoImage<'_> = GoImage {
            kind: ImageKind::Pe,
            endian: Endian::Little,
            ptr_size: 8,
            sections: vec![Section {
                name: ".rdata".to_owned(),
                address: base,
                data: &bytes,
            }],
            raw: &bytes,
            symbol_addrs: Vec::new(),
            flat: true,
        };
        assert_eq!(
            walk_moduledata(
                &image,
                base,
                ModuledataSource::SymbolRuntimeFirstmoduledata,
                PclntabVersion::Go120,
                None
            ),
            None
        );
    }

    #[test]
    fn find_subslice_locates_marker() {
        assert_eq!(
            find_subslice(b"xx\xff Go buildinf:yy", BUILDINFO_MARKER),
            Some(2)
        );
        assert_eq!(find_subslice(b"nope", BUILDINFO_MARKER), None);
    }
}
