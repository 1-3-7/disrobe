use std::collections::BTreeMap;
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::binary::GoImage;
use crate::error::{Error, Result};
use crate::pclntab::{LocatedPclntab, PclntabHeader, PclntabVersion, read_u32, read_u64};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoFunc {
    pub entry: u64,
    pub end: u64,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linker_symbol: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub abi0: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_line: Option<i32>,
}

impl GoFunc {
    #[must_use]
    pub const fn new(entry: u64, end: u64, name: String) -> Self {
        Self {
            entry,
            end,
            name,
            linker_symbol: None,
            abi0: false,
            start_line: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoSymbols {
    pub version_label: String,
    pub ptr_size: u8,
    pub funcs: Vec<GoFunc>,
    pub source_files: Vec<String>,
    pub package_set: Vec<String>,
}

pub fn parse_symbols(image: &GoImage<'_>, located: &LocatedPclntab<'_>) -> Result<GoSymbols> {
    let header: &PclntabHeader = &located.header;
    let body: &[u8] = located.data;
    let mut funcs: Vec<GoFunc> = Vec::new();
    let mut packages: BTreeSet<String> = BTreeSet::new();
    let mut files: BTreeSet<String> = BTreeSet::new();

    match header.version {
        PclntabVersion::Go12 => parse_go12(image, header, body, &mut funcs, &mut packages)?,
        PclntabVersion::Go116 => {
            parse_go116(image, header, body, &mut funcs, &mut packages, &mut files)?;
        }
        PclntabVersion::Go118 | PclntabVersion::Go120 => {
            parse_go118_plus(image, header, body, &mut funcs, &mut packages, &mut files)?;
        }
    }

    funcs.sort_by_key(|f: &GoFunc| f.entry);
    funcs.dedup_by(|a: &mut GoFunc, b: &mut GoFunc| a.entry == b.entry && a.name == b.name);

    enrich_with_linker_symbols(image, &mut funcs);

    Ok(GoSymbols {
        version_label: header.version.label().to_owned(),
        ptr_size: header.ptr_size,
        funcs,
        source_files: files.into_iter().collect(),
        package_set: packages.into_iter().collect(),
    })
}

const ABI_INTERNAL_SUFFIX: &str = ".abiinternal";
const ABI0_SUFFIX: &str = ".abi0";

fn strip_abi_suffix(symbol: &str) -> &str {
    symbol
        .strip_suffix(ABI0_SUFFIX)
        .or_else(|| symbol.strip_suffix(ABI_INTERNAL_SUFFIX))
        .unwrap_or(symbol)
}

fn linker_symbol_base(symbol: &str, macho: bool) -> &str {
    let stripped: &str = strip_abi_suffix(symbol);
    if macho {
        stripped.strip_prefix('_').unwrap_or(stripped)
    } else {
        stripped
    }
}

const GO_MIDDLE_DOT: char = '\u{00b7}';

fn base_matches_name(base: &str, func_name: &str) -> bool {
    if base == func_name {
        return true;
    }
    (base.contains(GO_MIDDLE_DOT) || func_name.contains(GO_MIDDLE_DOT))
        && base.replace(GO_MIDDLE_DOT, ".") == func_name.replace(GO_MIDDLE_DOT, ".")
}

const MIN_DELTA_CONSENSUS: usize = 8;

fn enrich_with_linker_symbols(image: &GoImage<'_>, funcs: &mut [GoFunc]) {
    if image.symbol_addrs.is_empty() || funcs.is_empty() {
        return;
    }
    let macho: bool = image.kind == crate::binary::ImageKind::MachO;
    let mut name_to_va: BTreeMap<&str, u64> = BTreeMap::new();
    for (name, va, _) in &image.symbol_addrs {
        if name.is_empty() || *va == 0 {
            continue;
        }
        name_to_va
            .entry(linker_symbol_base(name, macho))
            .or_insert(*va);
    }
    let Some(delta): Option<u64> = consensus_text_delta(funcs, &name_to_va) else {
        return;
    };
    let mut by_va: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
    for (name, va, _) in &image.symbol_addrs {
        if name.is_empty() || *va == 0 {
            continue;
        }
        by_va.entry(*va).or_default().push(name.as_str());
    }
    for func in funcs.iter_mut() {
        let abs_va: u64 = func.entry.wrapping_add(delta);
        let Some(candidates): Option<&Vec<&str>> = by_va.get(&abs_va) else {
            continue;
        };
        let mut chosen: Option<&str> = None;
        for symbol in candidates {
            if !base_matches_name(linker_symbol_base(symbol, macho), &func.name) {
                continue;
            }
            match chosen {
                None => chosen = Some(symbol),
                Some(prev) if prev == func.name && *symbol != func.name => chosen = Some(symbol),
                _ => {}
            }
        }
        let Some(symbol): Option<&str> = chosen else {
            continue;
        };
        if symbol.ends_with(ABI0_SUFFIX) {
            func.abi0 = true;
        }
        if symbol != func.name {
            func.linker_symbol = Some(symbol.to_owned());
        }
    }
}

fn consensus_text_delta(funcs: &[GoFunc], name_to_va: &BTreeMap<&str, u64>) -> Option<u64> {
    let mut tally: BTreeMap<u64, usize> = BTreeMap::new();
    for func in funcs {
        let Some(va): Option<&u64> = name_to_va.get(func.name.as_str()) else {
            continue;
        };
        let delta: u64 = va.wrapping_sub(func.entry);
        *tally.entry(delta).or_insert(0) += 1;
    }
    let (delta, count): (u64, usize) = tally.into_iter().max_by_key(|(_, c): &(u64, usize)| *c)?;
    (count >= MIN_DELTA_CONSENSUS).then_some(delta)
}

fn parse_go12(
    _image: &GoImage<'_>,
    header: &PclntabHeader,
    body: &[u8],
    funcs: &mut Vec<GoFunc>,
    packages: &mut BTreeSet<String>,
) -> Result<()> {
    let ps: usize = header.ptr_size as usize;
    let n: usize = bounded_func_count(header.n_funcs);
    let tab_off: usize = 8 + ps;
    let stride: usize = 2 * ps;
    if n == 0 || tab_off.saturating_add(n.saturating_mul(stride)) > body.len() {
        return Ok(());
    }
    funcs.reserve(bounded_func_prealloc(n));
    for i in 0..n {
        let entry_off: usize = tab_off + i * stride;
        let pc: u64 = read_word(body, entry_off, header)?;
        let funcoff_word: u64 = read_word(body, entry_off + ps, header)?;
        let Ok(funcoff): core::result::Result<usize, _> = usize::try_from(funcoff_word) else {
            continue;
        };
        if funcoff == 0 || funcoff >= body.len() {
            continue;
        }
        let name_off_field: usize = funcoff + ps;
        if name_off_field + 4 > body.len() {
            continue;
        }
        let nameoff: u32 = read_u32(body, name_off_field, header.endian)?;
        let name: String = read_cstring(body, nameoff as usize);
        if name.is_empty() {
            continue;
        }
        record_package(&name, packages);
        funcs.push(GoFunc::new(pc, pc, name));
    }
    fill_func_ends(funcs);
    Ok(())
}

fn parse_go116(
    image: &GoImage<'_>,
    header: &PclntabHeader,
    body: &[u8],
    funcs: &mut Vec<GoFunc>,
    packages: &mut BTreeSet<String>,
    files: &mut BTreeSet<String>,
) -> Result<()> {
    let n: usize = bounded_func_count(header.n_funcs);
    let ftab_off: usize = usize::try_from(header.filetab_off).unwrap_or(0);
    let funcname_off: usize = usize::try_from(header.funcname_off).unwrap_or(0);
    let funcdata_off: usize = usize::try_from(header.funcdata_off).unwrap_or(0);
    if n == 0 || funcdata_off >= body.len() {
        return Ok(());
    }
    let stride: usize = 2 * header.ptr_size as usize;
    let Some(ftab_size): Option<usize> =
        n.checked_add(1).and_then(|m: usize| m.checked_mul(stride))
    else {
        return Ok(());
    };
    if ftab_off
        .checked_add(ftab_size)
        .is_none_or(|end: usize| end > body.len())
    {
        return Ok(());
    }
    funcs.reserve(bounded_func_prealloc(n));
    for i in 0..n {
        let pos: usize = ftab_off + i * stride;
        let pc: u64 = read_word(body, pos, header)?;
        let funcoff_word: u64 = read_word(body, pos + header.ptr_size as usize, header)?;
        let Ok(off_native): core::result::Result<usize, _> = usize::try_from(funcoff_word) else {
            continue;
        };
        let Some(funcoff): Option<usize> = funcdata_off.checked_add(off_native) else {
            continue;
        };
        if funcoff
            .checked_add(8)
            .is_none_or(|end: usize| end > body.len())
        {
            continue;
        }
        let Some(nameoff_field): Option<usize> = funcoff.checked_add(header.ptr_size as usize)
        else {
            continue;
        };
        if nameoff_field
            .checked_add(4)
            .is_none_or(|end: usize| end > body.len())
        {
            continue;
        }
        let nameoff: u32 = read_u32(body, nameoff_field, header.endian)?;
        let name: String = read_cstring(body, funcname_off.saturating_add(nameoff as usize));
        if name.is_empty() {
            continue;
        }
        record_package(&name, packages);
        funcs.push(GoFunc::new(pc, pc, name));
    }
    fill_func_ends(funcs);
    collect_files_go116(image, header, body, files);
    Ok(())
}

fn parse_go118_plus(
    image: &GoImage<'_>,
    header: &PclntabHeader,
    body: &[u8],
    funcs: &mut Vec<GoFunc>,
    packages: &mut BTreeSet<String>,
    files: &mut BTreeSet<String>,
) -> Result<()> {
    let n: usize = bounded_func_count(header.n_funcs);
    let funcdata_off: usize = usize::try_from(header.funcdata_off).unwrap_or(0);
    let funcname_off: usize = usize::try_from(header.funcname_off).unwrap_or(0);
    let text_start: u64 = header.text_start;
    if n == 0 || funcdata_off >= body.len() {
        return Ok(());
    }
    let stride: usize = 8;
    let Some(ftab_size): Option<usize> =
        n.checked_add(1).and_then(|m: usize| m.checked_mul(stride))
    else {
        return Ok(());
    };
    if funcdata_off
        .checked_add(ftab_size)
        .is_none_or(|end: usize| end > body.len())
    {
        return Ok(());
    }
    funcs.reserve(bounded_func_prealloc(n));
    for i in 0..n {
        let pos: usize = funcdata_off + i * stride;
        let pc_off: u32 = read_u32(body, pos, header.endian)?;
        let funcoff: u32 = read_u32(body, pos + 4, header.endian)?;
        let pc: u64 = text_start.wrapping_add(u64::from(pc_off));
        let Some(func_struct_at): Option<usize> = funcdata_off.checked_add(funcoff as usize) else {
            continue;
        };
        if func_struct_at
            .checked_add(8)
            .is_none_or(|end: usize| end > body.len())
        {
            continue;
        }
        let Some(nameoff_field): Option<usize> = func_struct_at.checked_add(4) else {
            continue;
        };
        if nameoff_field
            .checked_add(4)
            .is_none_or(|end: usize| end > body.len())
        {
            continue;
        }
        let nameoff: u32 = read_u32(body, nameoff_field, header.endian)?;
        let name: String = read_cstring(body, funcname_off.saturating_add(nameoff as usize));
        if name.is_empty() {
            continue;
        }
        record_package(&name, packages);
        let start_line: Option<i32> = read_start_line(body, func_struct_at, header);
        let mut func: GoFunc = GoFunc::new(pc, pc, name);
        func.start_line = start_line;
        funcs.push(func);
    }
    fill_func_ends(funcs);
    collect_files_go118(image, header, body, files);
    Ok(())
}

const FUNC_STARTLINE_OFFSET: usize = 36;
const MAX_PLAUSIBLE_START_LINE: i32 = 1 << 26;

fn read_start_line(body: &[u8], func_struct_at: usize, header: &PclntabHeader) -> Option<i32> {
    if header.version != PclntabVersion::Go120 {
        return None;
    }
    let field: usize = func_struct_at.checked_add(FUNC_STARTLINE_OFFSET)?;
    let raw: u32 = read_u32(body, field, header.endian).ok()?;
    let line: i32 = i32::try_from(raw).ok()?;
    (1..=MAX_PLAUSIBLE_START_LINE)
        .contains(&line)
        .then_some(line)
}

const MAX_PLAUSIBLE_FUNCS: u64 = 16 * 1024 * 1024;
const MAX_FUNC_PREALLOC: usize = 1 << 16;

fn bounded_func_count(raw: u64) -> usize {
    if raw > MAX_PLAUSIBLE_FUNCS {
        return 0;
    }
    usize::try_from(raw).unwrap_or(0)
}

const fn bounded_func_prealloc(count: usize) -> usize {
    if count > MAX_FUNC_PREALLOC {
        MAX_FUNC_PREALLOC
    } else {
        count
    }
}

fn read_word(buf: &[u8], off: usize, header: &PclntabHeader) -> Result<u64> {
    match header.ptr_size {
        4 => read_u32(buf, off, header.endian).map(u64::from),
        8 => read_u64(buf, off, header.endian),
        other => Err(Error::PclntabInvariant(match other {
            0 => "ptr_size==0",
            _ => "ptr_size!=4|8",
        })),
    }
}

fn read_cstring(buf: &[u8], off: usize) -> String {
    if off >= buf.len() {
        return String::new();
    }
    let tail: &[u8] = &buf[off..];
    let end: usize = tail.iter().position(|b: &u8| *b == 0).unwrap_or(tail.len());
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

#[must_use]
pub fn package_path(symbol: &str) -> Option<&str> {
    let type_args_at: usize = symbol.find('[').unwrap_or(symbol.len());
    let head: &str = symbol.get(..type_args_at)?;
    let scan_start: usize = head.rfind('/').map_or(0, |slash: usize| slash + 1);
    let dot_rel: usize = head.get(scan_start..)?.find('.')?;
    let boundary: usize = scan_start + dot_rel;
    if boundary == 0 {
        return None;
    }
    if symbol.as_bytes().get(boundary + 1) == Some(&b'.') {
        return None;
    }
    let path: &str = symbol.get(..boundary)?;
    is_import_path_plausible(path).then_some(path)
}

fn is_import_path_plausible(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path
            .bytes()
            .all(|b: u8| !matches!(b, b':' | b'(' | b')' | b'*' | b',' | b' ' | b'\t'))
}

fn record_package(name: &str, packages: &mut BTreeSet<String>) {
    if let Some(path) = package_path(name) {
        packages.insert(path.to_owned());
    }
}

fn fill_func_ends(funcs: &mut [GoFunc]) {
    let mut sorted: Vec<usize> = (0..funcs.len()).collect();
    sorted.sort_by_key(|i: &usize| funcs[*i].entry);
    for window in sorted.windows(2) {
        let (a, b): (usize, usize) = (window[0], window[1]);
        let next: u64 = funcs[b].entry;
        funcs[a].end = next;
    }
    if let Some(last) = sorted.last().copied()
        && funcs[last].end == funcs[last].entry
    {
        funcs[last].end = funcs[last].entry.saturating_add(1);
    }
}

const MAX_FILETAB_ENTRY_LEN: usize = 4096;

fn collect_files_go116(
    _image: &GoImage<'_>,
    header: &PclntabHeader,
    body: &[u8],
    files: &mut BTreeSet<String>,
) {
    collect_files_via_cutab(header, body, files);
}

fn collect_files_go118(
    _image: &GoImage<'_>,
    header: &PclntabHeader,
    body: &[u8],
    files: &mut BTreeSet<String>,
) {
    collect_files_via_cutab(header, body, files);
}

fn collect_files_via_cutab(header: &PclntabHeader, body: &[u8], files: &mut BTreeSet<String>) {
    let filetab_off: usize = usize::try_from(header.filetab_off).unwrap_or(0);
    let pctab_off: usize = usize::try_from(header.pctab_off).unwrap_or(0);
    if filetab_off == 0 || pctab_off <= filetab_off || pctab_off > body.len() {
        return;
    }
    let cu_off: usize = usize::try_from(header.cu_off).unwrap_or(0);
    let reachable: BTreeSet<u32> = reachable_filetab_offsets(header, body, cu_off, filetab_off);
    let filetab: &[u8] = &body[filetab_off..pctab_off];
    if reachable.is_empty() {
        collect_filetab_blob(filetab, files);
        return;
    }
    for off in reachable {
        let path: String = read_cstring(filetab, off as usize);
        if is_source_file(&path) {
            files.insert(path);
        }
    }
}

fn reachable_filetab_offsets(
    header: &PclntabHeader,
    body: &[u8],
    cu_off: usize,
    filetab_off: usize,
) -> BTreeSet<u32> {
    let mut out: BTreeSet<u32> = BTreeSet::new();
    if cu_off == 0 || cu_off >= filetab_off {
        return out;
    }
    let cutab: &[u8] = &body[cu_off..filetab_off];
    let span: usize = filetab_off - cu_off;
    let mut pos: usize = 0;
    while pos + 4 <= span {
        if let Ok(value) = read_u32(cutab, pos, header.endian)
            && value != u32::MAX
        {
            out.insert(value);
        }
        pos += 4;
    }
    out
}

fn collect_filetab_blob(filetab: &[u8], files: &mut BTreeSet<String>) {
    let mut buf: Vec<u8> = Vec::new();
    for b in filetab {
        if *b == 0 {
            if !buf.is_empty()
                && let Ok(s) = std::str::from_utf8(&buf)
                && is_source_file(s)
            {
                files.insert(s.to_owned());
            }
            buf.clear();
        } else if buf.len() < MAX_FILETAB_ENTRY_LEN {
            buf.push(*b);
        }
    }
}

const SOURCE_EXTENSIONS: [&str; 5] = ["go", "s", "c", "h", "cpp"];

fn is_source_file(path: &str) -> bool {
    if path.is_empty() || path.len() > MAX_FILETAB_ENTRY_LEN {
        return false;
    }
    if path == "<autogenerated>" {
        return true;
    }
    std::path::Path::new(path)
        .extension()
        .and_then(|ext: &std::ffi::OsStr| ext.to_str())
        .is_some_and(|ext: &str| {
            SOURCE_EXTENSIONS
                .iter()
                .any(|known: &&str| ext.eq_ignore_ascii_case(known))
        })
}

#[must_use]
pub fn package_histogram(syms: &GoSymbols) -> BTreeMap<String, usize> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for f in &syms.funcs {
        if let Some(path) = package_path(&f.name) {
            *out.entry(path.to_owned()).or_insert(0) += 1;
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn package_path_recovers_dotted_import_paths() {
        assert_eq!(
            package_path("github.com/acme.corp/tool/internal/worker.Run"),
            Some("github.com/acme.corp/tool/internal/worker")
        );
        assert_eq!(
            package_path("github.com/acme.corp/tool/netutil.(*Conn).String"),
            Some("github.com/acme.corp/tool/netutil")
        );
        assert_eq!(package_path("net/http.(*Server).Serve"), Some("net/http"));
        assert_eq!(package_path("internal/abi.TypeOf"), Some("internal/abi"));
        assert_eq!(package_path("main.main"), Some("main"));
        assert_eq!(package_path("runtime.mallocgc"), Some("runtime"));
    }

    #[test]
    fn package_path_rejects_compiler_pseudo_symbols() {
        assert_eq!(package_path("type:.eq.[2]internal/abi.Method"), None);
        assert_eq!(package_path("go:itab.runtime.errorString,error"), None);
        assert_eq!(
            package_path("go:itab.internal/poll.errNetClosing,error"),
            None
        );
        assert_eq!(package_path("type..eq.runtime.g"), None);
        assert_eq!(package_path("main..inittask"), None);
    }

    #[test]
    fn package_path_rejects_bare_assembly_and_marker_symbols() {
        assert_eq!(package_path("aeshashbody"), None);
        assert_eq!(package_path("gogo"), None);
        assert_eq!(package_path("go:buildid"), None);
        assert_eq!(package_path("_rt0_amd64_windows"), None);
        assert_eq!(package_path(""), None);
    }

    #[test]
    fn package_path_cuts_type_arguments_before_boundary() {
        assert_eq!(package_path("main.Filter[github.com/x/y.T]"), Some("main"));
        assert_eq!(
            package_path("github.com/x/y/pkg.Map[go.shape.int]"),
            Some("github.com/x/y/pkg")
        );
    }

    #[test]
    fn linker_base_strips_macho_underscore_only_for_macho() {
        assert_eq!(linker_symbol_base("_aeshashbody", true), "aeshashbody");
        assert_eq!(
            linker_symbol_base("runtime.morestack.abi0", true),
            "runtime.morestack"
        );
        assert_eq!(linker_symbol_base("_aeshashbody", false), "_aeshashbody");
        assert_eq!(
            linker_symbol_base("runtime.morestack.abiinternal", false),
            "runtime.morestack"
        );
    }

    #[test]
    fn base_matches_bridges_go_middle_dot_and_elf_period() {
        assert!(base_matches_name(
            "type:.eq.runtime.untracedG.7",
            "type:.eq.runtime.untracedG\u{00b7}7"
        ));
        assert!(base_matches_name("main.main", "main.main"));
        assert!(!base_matches_name("main.main", "main.other"));
        assert!(!base_matches_name(
            "type:.eq.runtime.untracedG.7",
            "type:.eq.runtime.otherG\u{00b7}7"
        ));
    }

    #[test]
    fn source_file_classifier_accepts_go_and_autogenerated() {
        assert!(is_source_file("runtime/proc.go"));
        assert!(is_source_file("internal/abi/type.go"));
        assert!(is_source_file("asm_amd64.s"));
        assert!(is_source_file("<autogenerated>"));
        assert!(is_source_file("MAIN.GO"));
    }

    #[test]
    fn source_file_classifier_rejects_garbage() {
        assert!(!is_source_file(""));
        assert!(!is_source_file("runtime.main"));
        assert!(!is_source_file("not_a_path"));
        assert!(!is_source_file(&"x".repeat(MAX_FILETAB_ENTRY_LEN + 1)));
    }

    #[test]
    fn filetab_blob_splits_on_nul_and_filters() {
        let blob: &[u8] = b"a/b.go\0<autogenerated>\0garbageword\0c/d.s\0";
        let mut files: BTreeSet<String> = BTreeSet::new();
        collect_filetab_blob(blob, &mut files);
        assert!(files.contains("a/b.go"));
        assert!(files.contains("<autogenerated>"));
        assert!(files.contains("c/d.s"));
        assert!(!files.contains("garbageword"));
    }

    #[test]
    fn func_count_prealloc_is_capped() {
        let small: usize = 32;
        assert_eq!(bounded_func_prealloc(small), small);
        assert_eq!(
            bounded_func_prealloc(MAX_FUNC_PREALLOC + 1),
            MAX_FUNC_PREALLOC
        );
        assert_eq!(bounded_func_prealloc(usize::MAX), MAX_FUNC_PREALLOC);
    }

    fn startline_header(version: PclntabVersion) -> PclntabHeader {
        PclntabHeader {
            version,
            quantum: 1,
            ptr_size: 8,
            endian: crate::binary::Endian::Little,
            n_funcs: 1,
            n_files: 0,
            text_start: 0,
            funcname_off: 0,
            cu_off: 0,
            filetab_off: 0,
            pctab_off: 0,
            funcdata_off: 0,
            section_addr: 0,
            section_len: 0,
        }
    }

    #[test]
    fn start_line_read_only_for_go120_layout() {
        let mut body: Vec<u8> = vec![0u8; 64];
        body[FUNC_STARTLINE_OFFSET..FUNC_STARTLINE_OFFSET + 4]
            .copy_from_slice(&123u32.to_le_bytes());
        assert_eq!(
            read_start_line(&body, 0, &startline_header(PclntabVersion::Go120)),
            Some(123)
        );
        assert_eq!(
            read_start_line(&body, 0, &startline_header(PclntabVersion::Go118)),
            None
        );
    }

    #[test]
    fn start_line_rejects_out_of_bounds_and_implausible() {
        let short: Vec<u8> = vec![0u8; FUNC_STARTLINE_OFFSET + 2];
        assert_eq!(
            read_start_line(&short, 0, &startline_header(PclntabVersion::Go120)),
            None
        );

        let mut zero: Vec<u8> = vec![0u8; 64];
        zero[FUNC_STARTLINE_OFFSET..FUNC_STARTLINE_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            read_start_line(&zero, 0, &startline_header(PclntabVersion::Go120)),
            None
        );

        let mut huge: Vec<u8> = vec![0u8; 64];
        huge[FUNC_STARTLINE_OFFSET..FUNC_STARTLINE_OFFSET + 4]
            .copy_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert_eq!(
            read_start_line(&huge, 0, &startline_header(PclntabVersion::Go120)),
            None
        );
    }

    #[test]
    fn go116_saturated_funcoff_returns_without_panic() {
        let mut body: Vec<u8> = vec![0u8; 0x100];
        body[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());

        let image: GoImage<'_> = GoImage {
            kind: crate::binary::ImageKind::Pe,
            endian: crate::binary::Endian::Little,
            ptr_size: 8,
            sections: Vec::new(),
            raw: &body,
            symbol_addrs: Vec::new(),
            flat: false,
        };
        let header: PclntabHeader = PclntabHeader {
            version: PclntabVersion::Go116,
            quantum: 1,
            ptr_size: 8,
            endian: crate::binary::Endian::Little,
            n_funcs: 1,
            n_files: 0,
            text_start: 0,
            funcname_off: 0x80,
            cu_off: 0,
            filetab_off: 0x20,
            pctab_off: 0,
            funcdata_off: 0x40,
            section_addr: 0,
            section_len: body.len(),
        };
        let result: std::thread::Result<Result<()>> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut funcs: Vec<GoFunc> = Vec::new();
                let mut packages: BTreeSet<String> = BTreeSet::new();
                let mut files: BTreeSet<String> = BTreeSet::new();
                parse_go116(
                    &image,
                    &header,
                    &body,
                    &mut funcs,
                    &mut packages,
                    &mut files,
                )
            }));

        assert!(result.is_ok(), "saturated funcoff must not panic");
        assert!(result.unwrap().is_ok());
    }
}
