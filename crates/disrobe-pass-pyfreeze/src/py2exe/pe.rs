use object::LittleEndian as LE;
use object::pe::{ImageNtHeaders32, ImageNtHeaders64, ImageResourceDataEntry};
use object::read::pe::{
    ImageNtHeaders, PeFile, ResourceDirectory, ResourceDirectoryEntryData, ResourceDirectoryTable,
    ResourceNameOrId,
};

use crate::error::{Error, Result};

const PYTHONSCRIPT_TYPE: &str = "PYTHONSCRIPT";
const PYTHONSCRIPT_ID: u16 = 1;
const MAX_PYTHONSCRIPT_BYTES: usize = 64 * 1024 * 1024;

pub fn extract_pythonscript_resource(bytes: &[u8]) -> Result<Vec<u8>> {
    if !looks_like_pe(bytes) {
        return Err(Error::PeParse(
            "input is not a PE (missing MZ magic)".to_owned(),
        ));
    }
    match object::FileKind::parse(bytes).map_err(pe_error)? {
        object::FileKind::Pe32 => pythonscript_resource::<ImageNtHeaders32>(bytes),
        object::FileKind::Pe64 => pythonscript_resource::<ImageNtHeaders64>(bytes),
        other => Err(Error::PeParse(format!(
            "input is {other:?}, not a PE image"
        ))),
    }
}

fn pe_error(error: object::Error) -> Error {
    Error::PeParse(error.to_string())
}

fn pythonscript_resource<Pe: ImageNtHeaders>(bytes: &[u8]) -> Result<Vec<u8>> {
    let file: PeFile<'_, Pe> = PeFile::parse(bytes).map_err(pe_error)?;
    let sections = file.section_table();
    let directory: ResourceDirectory<'_> = file
        .data_directories()
        .resource_directory(bytes, &sections)
        .map_err(pe_error)?
        .ok_or(Error::Py2exeScriptResourceMissing)?;
    let root: ResourceDirectoryTable<'_> = directory.root().map_err(pe_error)?;
    let mut script_type: Option<ResourceDirectoryTable<'_>> = None;
    for entry in root.entries {
        if let ResourceNameOrId::Name(name) = entry.name_or_id()
            && name.to_string_lossy(directory).map_err(pe_error)? == PYTHONSCRIPT_TYPE
        {
            script_type = entry.data(directory).map_err(pe_error)?.table();
            break;
        }
    }
    let script_type: ResourceDirectoryTable<'_> =
        script_type.ok_or(Error::Py2exeScriptResourceMissing)?;
    let script_entry = script_type
        .entries
        .iter()
        .find(|entry| matches!(entry.name_or_id(), ResourceNameOrId::Id(PYTHONSCRIPT_ID)))
        .ok_or(Error::Py2exeScriptResourceMissing)?;
    let data_entry: &ImageResourceDataEntry =
        match script_entry.data(directory).map_err(pe_error)? {
            ResourceDirectoryEntryData::Data(data) => data,
            ResourceDirectoryEntryData::Table(languages) => languages
                .entries
                .first()
                .map(|language| language.data(directory))
                .transpose()
                .map_err(pe_error)?
                .and_then(ResourceDirectoryEntryData::data)
                .ok_or(Error::Py2exeScriptResourceMissing)?,
        };
    let size: usize = usize::try_from(data_entry.size.get(LE))
        .map_err(|_| Error::PeParse("PYTHONSCRIPT size exceeds host range".to_owned()))?;
    if size > MAX_PYTHONSCRIPT_BYTES {
        return Err(Error::PeParse(format!(
            "PYTHONSCRIPT declares {size} bytes, above the {MAX_PYTHONSCRIPT_BYTES} byte cap"
        )));
    }
    let at_rva: &[u8] = sections
        .pe_data_at(bytes, data_entry.offset_to_data.get(LE))
        .ok_or_else(|| Error::PeParse("PYTHONSCRIPT data lies outside every section".to_owned()))?;
    let script: &[u8] = at_rva
        .get(..size)
        .ok_or_else(|| Error::PeParse("PYTHONSCRIPT data runs past its section".to_owned()))?;
    Ok(script.to_vec())
}

#[must_use]
pub fn sniff_python_version(bytes: &[u8]) -> Option<(u8, u8)> {
    let needle: &[u8] = b"python";
    let mut idx: usize = 0;
    while let Some(pos) = bytes[idx..]
        .windows(needle.len())
        .position(|w: &[u8]| w.eq_ignore_ascii_case(needle))
    {
        let start: usize = idx + pos + needle.len();
        if let Some(version) = parse_python_dll_version(&bytes[start..]) {
            return Some(version);
        }
        idx = idx + pos + 1;
        if idx + needle.len() > bytes.len() {
            break;
        }
    }
    None
}

fn parse_python_dll_version(tail: &[u8]) -> Option<(u8, u8)> {
    let digits: Vec<u8> = tail
        .iter()
        .take(3)
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    let suffix: &[u8] = &tail[digits.len()..tail.len().min(digits.len() + 4)];
    if !suffix.eq_ignore_ascii_case(b".dll") {
        return None;
    }
    match digits.as_slice() {
        [major, minor] => Some((major - b'0', minor - b'0')),
        [major, minor, patch] => {
            let major_val: u8 = major - b'0';
            if major_val >= 3 {
                Some((major_val, (minor - b'0') * 10 + (patch - b'0')))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[must_use]
pub fn looks_like_pe(bytes: &[u8]) -> bool {
    if bytes.len() < 0x40 {
        return false;
    }
    if &bytes[..2] != b"MZ" {
        return false;
    }
    let Some(pe_offset): Option<usize> = usize::try_from(u32::from_le_bytes([
        bytes[0x3C],
        bytes[0x3D],
        bytes[0x3E],
        bytes[0x3F],
    ]))
    .ok() else {
        return false;
    };
    let Some(pe_end): Option<usize> = pe_offset.checked_add(4) else {
        return false;
    };
    bytes.get(pe_offset..pe_end) == Some(&b"PE\0\0"[..])
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        let err: Error = extract_pythonscript_resource(b"not a pe").unwrap_err();
        assert!(matches!(err, Error::PeParse(_)));
    }

    #[test]
    fn detects_minimal_pe() {
        let mut buf: Vec<u8> = vec![0u8; 0x80];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert!(looks_like_pe(&buf));
    }

    #[test]
    fn sniffs_python3_dll_version() {
        let buf: Vec<u8> = b"\x00\x00MZjunk python314.dll trailer".to_vec();
        assert_eq!(sniff_python_version(&buf), Some((3, 14)));
    }

    #[test]
    fn sniffs_python2_dll_version() {
        let buf: Vec<u8> = b"prefix PYTHON27.DLL suffix".to_vec();
        assert_eq!(sniff_python_version(&buf), Some((2, 7)));
    }

    #[test]
    fn ignores_non_dll_python_strings() {
        let buf: Vec<u8> = b"pythonpath=/usr/lib/python3".to_vec();
        assert_eq!(sniff_python_version(&buf), None);
    }

    #[test]
    fn a_magic_tag_outside_the_resource_directory_is_not_a_script() {
        let mut buf: Vec<u8> = vec![0u8; 0x80];
        buf[0..2].copy_from_slice(b"MZ");
        buf[0x3C..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        buf[0x40..0x44].copy_from_slice(b"PE\0\0");
        buf.extend_from_slice(&crate::py2exe::scriptinfo::PY2EXE_MAGIC_TAG.to_le_bytes());
        buf.extend_from_slice(b"app.zip\0");
        assert!(extract_pythonscript_resource(&buf).is_err());
    }
}
