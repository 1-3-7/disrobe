use crate::error::{Error, Result};

pub const AR_MAGIC: &[u8; 8] = b"!<arch>\n";

const HEADER_LEN: usize = 60;
const NAME_FIELD: usize = 16;
const SIZE_OFFSET: usize = 48;
const SIZE_LEN: usize = 10;
const FMAG_OFFSET: usize = 58;
const FMAG: &[u8; 2] = b"\x60\n";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArMember {
    pub name: String,
    pub offset: usize,
    pub size: usize,
    pub is_special: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArArchive {
    pub members: Vec<ArMember>,
}

#[must_use]
pub fn detect_ar(bytes: &[u8]) -> bool {
    bytes.starts_with(AR_MAGIC)
}

pub fn parse_ar(bytes: &[u8]) -> Result<ArArchive> {
    if !detect_ar(bytes) {
        return Err(Error::Ar("ar: missing !<arch>\\n global header".to_owned()));
    }
    let mut offset: usize = AR_MAGIC.len();
    let mut long_names: Vec<u8> = Vec::new();
    let mut members: Vec<ArMember> = Vec::new();
    while offset + HEADER_LEN <= bytes.len() {
        if bytes[offset] == b'\n' {
            offset += 1;
            continue;
        }
        let header: &[u8] = &bytes[offset..offset + HEADER_LEN];
        if &header[FMAG_OFFSET..FMAG_OFFSET + 2] != FMAG {
            return Err(Error::Ar(format!(
                "ar: member header at offset {offset} missing 0x60 0x0a terminator"
            )));
        }
        let raw_name: &[u8] = &header[..NAME_FIELD];
        let size: usize = parse_ar_size(&header[SIZE_OFFSET..SIZE_OFFSET + SIZE_LEN])?;
        let data_start: usize = offset + HEADER_LEN;
        let data_end: usize = data_start
            .checked_add(size)
            .ok_or_else(|| Error::Ar("ar: member size overflow".to_owned()))?;
        if data_end > bytes.len() {
            return Err(Error::Ar(format!(
                "ar: member `{}` data (size {size}) runs past end of archive",
                String::from_utf8_lossy(raw_name).trim_end()
            )));
        }
        let trimmed_name: &[u8] = trim_trailing_spaces(raw_name);
        if trimmed_name == b"//" {
            long_names = bytes[data_start..data_end].to_vec();
            members.push(ArMember {
                name: "//".to_owned(),
                offset: data_start,
                size,
                is_special: true,
            });
        } else if trimmed_name == b"/" || trimmed_name == b"/SYM64/" {
            members.push(ArMember {
                name: String::from_utf8_lossy(trimmed_name).into_owned(),
                offset: data_start,
                size,
                is_special: true,
            });
        } else {
            let resolved: String = resolve_ar_name(trimmed_name, &long_names)?;
            members.push(ArMember {
                name: resolved,
                offset: data_start,
                size,
                is_special: false,
            });
        }
        offset = data_end + (data_end & 1);
    }
    if members.is_empty() {
        return Err(Error::Ar("ar: archive contains no members".to_owned()));
    }
    Ok(ArArchive { members })
}

fn parse_ar_size(field: &[u8]) -> Result<usize> {
    let text: &str = core::str::from_utf8(trim_trailing_spaces(field))
        .map_err(|e| Error::Ar(format!("ar: non-ascii size field: {e}")))?;
    if text.is_empty() {
        return Ok(0);
    }
    text.parse::<usize>()
        .map_err(|e| Error::Ar(format!("ar: bad decimal size `{text}`: {e}")))
}

fn resolve_ar_name(raw: &[u8], long_names: &[u8]) -> Result<String> {
    if let Some(rest) = raw.strip_prefix(b"/")
        && rest.iter().all(u8::is_ascii_digit)
        && !rest.is_empty()
    {
        let index: usize = core::str::from_utf8(rest)
            .ok()
            .and_then(|s: &str| s.parse::<usize>().ok())
            .ok_or_else(|| Error::Ar("ar: bad long-name index".to_owned()))?;
        return Ok(read_long_name(long_names, index));
    }
    if let Some(rest) = raw.strip_prefix(b"#1/")
        && rest.iter().all(u8::is_ascii_digit)
        && !rest.is_empty()
    {
        return Ok(format!("#1/{}", String::from_utf8_lossy(rest)));
    }
    let trimmed: &[u8] = raw.strip_suffix(b"/").map_or(raw, |value: &[u8]| value);
    Ok(String::from_utf8_lossy(trimmed).into_owned())
}

fn read_long_name(table: &[u8], index: usize) -> String {
    let tail: &[u8] = table
        .get(index..)
        .map_or(&[] as &[u8], |value: &[u8]| value);
    let end: usize = tail
        .iter()
        .position(|&b: &u8| b == b'\n' || b == b'/')
        .map_or(tail.len(), |value: usize| value);
    String::from_utf8_lossy(&tail[..end]).into_owned()
}

fn trim_trailing_spaces(field: &[u8]) -> &[u8] {
    let mut end: usize = field.len();
    while end > 0 && field[end - 1] == b' ' {
        end -= 1;
    }
    &field[..end]
}

#[must_use]
pub fn member_bytes<'a>(bytes: &'a [u8], member: &ArMember) -> Option<&'a [u8]> {
    bytes.get(member.offset..member.offset + member.size)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn build_member(name: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(name);
        out.extend_from_slice(b"0           ");
        out.extend_from_slice(b"0     ");
        out.extend_from_slice(b"0     ");
        out.extend_from_slice(b"100644  ");
        let size_field: String = format!("{:<10}", data.len());
        out.extend_from_slice(size_field.as_bytes());
        out.extend_from_slice(FMAG);
        out.extend_from_slice(data);
        if data.len() & 1 == 1 {
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn parses_short_named_members() {
        let mut ar: Vec<u8> = AR_MAGIC.to_vec();
        ar.extend(build_member(b"hello.txt/      ", b"hi"));
        ar.extend(build_member(b"data.bin/       ", b"abc"));
        let archive: ArArchive = parse_ar(&ar).expect("parse");
        let files: Vec<&ArMember> = archive.members.iter().filter(|m| !m.is_special).collect();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].name, "hello.txt");
        assert_eq!(member_bytes(&ar, files[0]), Some(&b"hi"[..]));
        assert_eq!(member_bytes(&ar, files[1]), Some(&b"abc"[..]));
    }

    #[test]
    fn resolves_gnu_long_name_table() {
        let long_table: &[u8] = b"this_is_a_very_long_member_name.txt/\n";
        let mut ar: Vec<u8> = AR_MAGIC.to_vec();
        ar.extend(build_member(b"//              ", long_table));
        ar.extend(build_member(b"/0              ", b"payload"));
        let archive: ArArchive = parse_ar(&ar).expect("parse");
        let file: &ArMember = archive
            .members
            .iter()
            .find(|m| !m.is_special)
            .expect("file member");
        assert_eq!(file.name, "this_is_a_very_long_member_name.txt");
        assert_eq!(member_bytes(&ar, file), Some(&b"payload"[..]));
    }

    #[test]
    fn symbol_table_member_marked_special() {
        let mut ar: Vec<u8> = AR_MAGIC.to_vec();
        ar.extend(build_member(b"/               ", b"\x00\x00\x00\x00"));
        ar.extend(build_member(b"obj.o/          ", b"ELF"));
        let archive: ArArchive = parse_ar(&ar).expect("parse");
        assert!(archive.members[0].is_special);
        assert_eq!(archive.members[0].name, "/");
        assert!(!archive.members[1].is_special);
    }

    #[test]
    fn rejects_non_ar() {
        assert!(parse_ar(b"not an ar archive at all really").is_err());
    }
}
