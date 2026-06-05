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

    Ok(GoSymbols {
        version_label: header.version.label().to_owned(),
        ptr_size: header.ptr_size,
        funcs,
        source_files: files.into_iter().collect(),
        package_set: packages.into_iter().collect(),
    })
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
    funcs.reserve(n);
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
        funcs.push(GoFunc {
            entry: pc,
            end: pc,
            name,
        });
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
    funcs.reserve(n);
    for i in 0..n {
        let pos: usize = ftab_off + i * stride;
        let pc: u64 = read_word(body, pos, header)?;
        let funcoff_word: u64 = read_word(body, pos + header.ptr_size as usize, header)?;
        let Ok(off_native): core::result::Result<usize, _> = usize::try_from(funcoff_word) else {
            continue;
        };
        let funcoff: usize = funcdata_off.saturating_add(off_native);
        if funcoff + 4 > body.len() {
            continue;
        }
        if funcoff + 8 > body.len() {
            continue;
        }
        let nameoff_field: usize = funcoff + header.ptr_size as usize;
        if nameoff_field + 4 > body.len() {
            continue;
        }
        let nameoff: u32 = read_u32(body, nameoff_field, header.endian)?;
        let name: String = read_cstring(body, funcname_off.saturating_add(nameoff as usize));
        if name.is_empty() {
            continue;
        }
        record_package(&name, packages);
        funcs.push(GoFunc {
            entry: pc,
            end: pc,
            name,
        });
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
    funcs.reserve(n);
    for i in 0..n {
        let pos: usize = funcdata_off + i * stride;
        let pc_off: u32 = read_u32(body, pos, header.endian)?;
        let funcoff: u32 = read_u32(body, pos + 4, header.endian)?;
        let pc: u64 = text_start.wrapping_add(u64::from(pc_off));
        let func_struct_at: usize = funcdata_off.saturating_add(funcoff as usize);
        if func_struct_at + 8 > body.len() {
            continue;
        }
        let nameoff_field: usize = func_struct_at + 4;
        if nameoff_field + 4 > body.len() {
            continue;
        }
        let nameoff: u32 = read_u32(body, nameoff_field, header.endian)?;
        let name: String = read_cstring(body, funcname_off.saturating_add(nameoff as usize));
        if name.is_empty() {
            continue;
        }
        record_package(&name, packages);
        funcs.push(GoFunc {
            entry: pc,
            end: pc,
            name,
        });
    }
    fill_func_ends(funcs);
    collect_files_go118(image, header, body, files);
    Ok(())
}

const MAX_PLAUSIBLE_FUNCS: u64 = 16 * 1024 * 1024;

fn bounded_func_count(raw: u64) -> usize {
    if raw > MAX_PLAUSIBLE_FUNCS {
        return 0;
    }
    usize::try_from(raw).unwrap_or(0)
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

fn record_package(name: &str, packages: &mut BTreeSet<String>) {
    if let Some(idx) = name.find('.') {
        let candidate: &str = &name[..idx];
        if !candidate.is_empty() && !candidate.contains(' ') {
            packages.insert(candidate.to_owned());
        }
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

fn collect_files_go116(
    _image: &GoImage<'_>,
    header: &PclntabHeader,
    body: &[u8],
    files: &mut BTreeSet<String>,
) {
    let ftab_off: usize = usize::try_from(header.filetab_off).unwrap_or(0);
    let n: usize = bounded_func_count(header.n_files);
    let table_span: Option<usize> = n
        .checked_mul(4)
        .and_then(|s: usize| ftab_off.checked_add(s));
    if ftab_off == 0 || n == 0 || table_span.is_none_or(|end: usize| end > body.len()) {
        return;
    }
    for i in 0..n {
        let pos: usize = ftab_off + i * 4;
        let Ok(off): Result<u32> = read_u32(body, pos, header.endian) else {
            continue;
        };
        let path: String = read_cstring(body, ftab_off.saturating_add(off as usize));
        if !path.is_empty() {
            files.insert(path);
        }
    }
}

fn collect_files_go118(
    image: &GoImage<'_>,
    header: &PclntabHeader,
    body: &[u8],
    files: &mut BTreeSet<String>,
) {
    let _ = image;
    let _ = header;
    let mut start: usize = 0;
    let mut buf: Vec<u8> = Vec::new();
    for (i, b) in body.iter().enumerate() {
        if *b == 0 {
            if !buf.is_empty()
                && looks_like_source_path(&buf)
                && let Ok(s) = std::str::from_utf8(&buf)
            {
                files.insert(s.to_owned());
            }
            buf.clear();
            start = i + 1;
        } else if buf.len() < 4096 {
            buf.push(*b);
        }
    }
    let _ = start;
}

fn looks_like_source_path(buf: &[u8]) -> bool {
    if buf.len() < 4 {
        return false;
    }
    let has_slash: bool = buf.contains(&b'/') || buf.contains(&b'\\');
    let ends_go: bool = buf.ends_with(b".go") || buf.ends_with(b".s");
    has_slash && ends_go
}

pub fn package_histogram(syms: &GoSymbols) -> BTreeMap<String, usize> {
    let mut out: BTreeMap<String, usize> = BTreeMap::new();
    for f in &syms.funcs {
        if let Some(idx) = f.name.find('.') {
            let pkg: &str = &f.name[..idx];
            if !pkg.is_empty() {
                *out.entry(pkg.to_owned()).or_insert(0) += 1;
            }
        }
    }
    out
}
