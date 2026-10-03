use std::ops::Range;

use disrobe_bytes::read_uleb128_at;
use serde::Serialize;
use wasmparser::{IndirectNaming, KnownCustom, Name, Naming, Parser, Payload};

use super::NameStrategy;
use crate::error::{Error, Result};

const MAX_SECTION_HEADER_BYTES: usize = 5;
const MAX_MODULE_BYTES: usize = 64 * 1024 * 1024;
const HEX_NAME_CHARS: usize = 16;
const ALPHANUMERAL_NAME_CHARS: usize = 24;
const ALTERNATING_NAME_CHARS: usize = 32;
const ALTERNATING_SETS: [[char; 4]; 2] = [['u', 'ú', 'ü', 'û'], ['ø', 'ó', 'ö', 'ô']];
const MAX_GENERATED_NAMES: usize = 65_536;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NameStripStats {
    pub function_names_dropped: usize,
    pub local_names_dropped: usize,
}

struct GeneratedNames {
    style: NameStrategy,
    function_names: usize,
    local_names: usize,
}

pub fn obfuscated_name_style(wasm: &[u8]) -> Result<Option<NameStrategy>> {
    check_module_size(wasm.len())?;
    for payload in Parser::new(0).parse_all(wasm) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        if let Payload::CustomSection(reader) = payload
            && let KnownCustom::Name(names) = reader.as_known()
            && let Some(found) = generated_names(names)?
        {
            return Ok(Some(found.style));
        }
    }
    Ok(None)
}

pub fn strip_obfuscated_names(wasm: &[u8]) -> Result<(Vec<u8>, NameStripStats)> {
    check_module_size(wasm.len())?;
    let mut dropped: Vec<Range<usize>> = Vec::new();
    let mut stats: NameStripStats = NameStripStats::default();
    for payload in Parser::new(0).parse_all(wasm) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        let Payload::CustomSection(reader) = payload else {
            continue;
        };
        let KnownCustom::Name(names) = reader.as_known() else {
            continue;
        };
        let Some(found) = generated_names(names)? else {
            continue;
        };
        let content: Range<usize> = reader.range();
        let start: usize = section_start(wasm, &content).ok_or_else(|| {
            Error::Parse(format!(
                "name section at {} has no well-formed section header",
                content.start
            ))
        })?;
        dropped.push(start..content.end);
        stats.function_names_dropped = checked_total_name_count(
            stats.function_names_dropped,
            found.function_names,
            "function",
        )?;
        stats.local_names_dropped =
            checked_total_name_count(stats.local_names_dropped, found.local_names, "local")?;
    }
    if dropped.is_empty() {
        return Ok((wasm.to_vec(), stats));
    }
    let mut kept: Vec<u8> = Vec::with_capacity(wasm.len());
    let mut cursor: usize = 0;
    for range in dropped {
        kept.extend_from_slice(&wasm[cursor..range.start]);
        cursor = range.end;
    }
    kept.extend_from_slice(&wasm[cursor..]);
    Ok((kept, stats))
}

const fn check_module_size(size: usize) -> Result<()> {
    if size > MAX_MODULE_BYTES {
        return Err(Error::ModuleInputLimit {
            actual: size,
            limit: MAX_MODULE_BYTES,
        });
    }
    Ok(())
}

fn section_start(wasm: &[u8], content: &Range<usize>) -> Option<usize> {
    let size: u64 = u64::try_from(content.len()).ok()?;
    (1..=MAX_SECTION_HEADER_BYTES).find_map(|leb_len: usize| {
        let id_at: usize = content.start.checked_sub(leb_len + 1)?;
        let (value, consumed): (u64, usize) = read_uleb128_at(wasm, id_at + 1).ok()?;
        (wasm.get(id_at) == Some(&0) && value == size && consumed == leb_len).then_some(id_at)
    })
}

fn generated_names(names: wasmparser::NameSectionReader<'_>) -> Result<Option<GeneratedNames>> {
    let mut style: Option<NameStrategy> = None;
    let mut function_names: usize = 0;
    let mut local_names: usize = 0;
    let mut agree = |name: &str| -> bool {
        let Some(found) = generator_style(name) else {
            return false;
        };
        *style.get_or_insert(found) == found
    };
    for subsection in names {
        match subsection.map_err(|error| Error::Parse(error.to_string()))? {
            Name::Function(map) => {
                for naming in map {
                    let naming: Naming<'_> =
                        naming.map_err(|error| Error::Parse(error.to_string()))?;
                    if !agree(naming.name) {
                        return Ok(None);
                    }
                    function_names = checked_name_count(function_names)?;
                }
            }
            Name::Local(groups) => {
                for group in groups {
                    let group: IndirectNaming<'_> =
                        group.map_err(|error| Error::Parse(error.to_string()))?;
                    for naming in group.names {
                        let naming: Naming<'_> =
                            naming.map_err(|error| Error::Parse(error.to_string()))?;
                        if !agree(naming.name) {
                            return Ok(None);
                        }
                        local_names = checked_name_count(local_names)?;
                    }
                }
            }
            _ => return Ok(None),
        }
    }
    let Some(style): Option<NameStrategy> = style else {
        return Ok(None);
    };
    Ok((function_names > 0).then_some(GeneratedNames {
        style,
        function_names,
        local_names,
    }))
}

fn checked_name_count(count: usize) -> Result<usize> {
    let next: usize = count
        .checked_add(1)
        .ok_or_else(|| Error::Parse("generated name count overflow".to_owned()))?;
    if next > MAX_GENERATED_NAMES {
        return Err(Error::Parse(format!(
            "generated name count exceeds {MAX_GENERATED_NAMES}"
        )));
    }
    Ok(next)
}

fn checked_total_name_count(current: usize, added: usize, kind: &'static str) -> Result<usize> {
    current.checked_add(added).ok_or_else(|| {
        Error::Parse(format!(
            "generated {kind} name count overflow across name sections"
        ))
    })
}

fn generator_style(name: &str) -> Option<NameStrategy> {
    let bytes: &[u8] = name.as_bytes();
    if bytes.len() == HEX_NAME_CHARS
        && bytes
            .iter()
            .all(|b: &u8| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Some(NameStrategy::Hex);
    }
    if bytes.len() == ALPHANUMERAL_NAME_CHARS
        && bytes
            .iter()
            .all(|b: &u8| b.is_ascii_digit() || b.is_ascii_lowercase())
    {
        return Some(NameStrategy::Alphanum);
    }
    let alternating: bool = name.chars().count() == ALTERNATING_NAME_CHARS
        && ALTERNATING_SETS
            .iter()
            .any(|set: &[char; 4]| name.chars().all(|c: char| set.contains(&c)));
    alternating.then_some(NameStrategy::Homoglyph)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn custom_section(name: &str, contents: &[u8]) -> Vec<u8> {
        let mut payload: Vec<u8> = Vec::with_capacity(name.len() + contents.len() + 1);
        payload.push(u8::try_from(name.len()).expect("short test section name"));
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(contents);
        let mut section: Vec<u8> = Vec::with_capacity(payload.len() + 2);
        section.push(0);
        section.push(u8::try_from(payload.len()).expect("short test section payload"));
        section.extend_from_slice(&payload);
        section
    }

    fn generated_function_name_section(name: &str) -> Vec<u8> {
        let mut subsection: Vec<u8> = vec![1, 0, 1, 0];
        subsection.push(u8::try_from(name.len()).expect("short test function name"));
        subsection.extend_from_slice(name.as_bytes());
        subsection[1] = u8::try_from(subsection.len() - 2).expect("short test subsection");
        custom_section("name", &subsection)
    }

    #[test]
    fn strips_only_recognized_generated_name_sections() {
        let mut wasm: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();
        let generated: Vec<u8> = generated_function_name_section("602f24b28d315f0a");
        let retained_name: Vec<u8> = custom_section("name", &[0, 5, 4, b'k', b'e', b'e', b'p']);
        let retained_custom: Vec<u8> = custom_section("producers", &[7]);
        wasm.extend_from_slice(&retained_name);
        wasm.extend_from_slice(&generated);
        wasm.extend_from_slice(&retained_custom);

        assert_eq!(
            obfuscated_name_style(&wasm).expect("well-formed generated name section"),
            Some(NameStrategy::Hex)
        );
        let (stripped, stats): (Vec<u8>, NameStripStats) =
            strip_obfuscated_names(&wasm).expect("well-formed test module");
        let mut expected: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();
        expected.extend_from_slice(&retained_name);
        expected.extend_from_slice(&retained_custom);
        assert_eq!(stripped, expected);
        assert_eq!(stats.function_names_dropped, 1);
        assert_eq!(stats.local_names_dropped, 0);
    }

    #[test]
    fn malformed_modules_return_typed_parse_errors() {
        assert!(matches!(
            strip_obfuscated_names(b"\0asm\x01\0\0\0\0\x80"),
            Err(Error::Parse(_))
        ));

        let mut malformed_name: Vec<u8> = b"\0asm\x01\0\0\0".to_vec();
        malformed_name.extend_from_slice(&custom_section("name", &[1, 1, 0x80]));
        assert!(matches!(
            strip_obfuscated_names(&malformed_name),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn rejects_modules_larger_than_the_helper_limit() {
        assert!(matches!(
            check_module_size(MAX_MODULE_BYTES + 1),
            Err(Error::ModuleInputLimit {
                actual,
                limit: MAX_MODULE_BYTES,
            }) if actual == MAX_MODULE_BYTES + 1
        ));
    }

    #[test]
    fn generator_alphabets_are_exact() {
        assert_eq!(generator_style("602f24b28d315f0a"), Some(NameStrategy::Hex));
        assert_eq!(
            generator_style("3juyyhmg5ckmfingh7yxokhs"),
            Some(NameStrategy::Alphanum)
        );
        assert_eq!(
            generator_style("uúüûuúüûuúüûuúüûuúüûuúüûuúüûuúüû"),
            Some(NameStrategy::Homoglyph)
        );
        assert_eq!(
            generator_style("øóöôøóöôøóöôøóöôøóöôøóöôøóöôøóöô"),
            Some(NameStrategy::Homoglyph)
        );
        assert_eq!(generator_style("602F24B28D315F0A"), None);
        assert_eq!(generator_style("602f24b28d315f0"), None);
        assert_eq!(generator_style("uúüûuúüûuúüûuúüûøóöôøóöôøóöôøóöô"), None);
        assert_eq!(generator_style("sum_of_squares"), None);
    }
}
