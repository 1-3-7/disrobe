use crate::error::{Error, Result};
use crate::object::Object;
use crate::version::{PyVersion, magic_for, pyversion_from_magic};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PycHeader {
    pub version: PyVersion,
    pub magic: u32,
    pub bit_field: Option<u32>,
    pub timestamp: u32,
    pub source_size: Option<u32>,
}

impl PycHeader {
    pub fn deterministic(version: PyVersion) -> Result<Self> {
        let magic: u32 = magic_for(version).ok_or(Error::UnsupportedPyVersion(version))?;
        Ok(Self {
            version,
            magic,
            bit_field: if version.has_pep552_header() {
                Some(0)
            } else {
                None
            },
            timestamp: 0,
            source_size: if version.has_source_size() {
                Some(0)
            } else {
                None
            },
        })
    }

    #[must_use]
    pub const fn header_len(&self) -> usize {
        self.version.pyc_header_len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PycFile {
    pub header: PycHeader,
    pub code: Object,
}

pub fn write_pyc(file: &PycFile) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(2048);
    out.extend_from_slice(&file.header.magic.to_le_bytes());

    if let Some(bf) = file.header.bit_field {
        out.extend_from_slice(&bf.to_le_bytes());
        out.extend_from_slice(&file.header.timestamp.to_le_bytes());
        let source_size: u32 = file.header.source_size.map_or(0, |value: u32| value);
        out.extend_from_slice(&source_size.to_le_bytes());
    } else if let Some(size) = file.header.source_size {
        out.extend_from_slice(&file.header.timestamp.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
    } else {
        out.extend_from_slice(&file.header.timestamp.to_le_bytes());
    }

    let marshaled: Vec<u8> = crate::writer::dump(&file.code, file.header.version)?;
    out.extend(marshaled);
    Ok(out)
}

pub fn read_pyc(bytes: &[u8]) -> Result<PycFile> {
    if bytes.len() < 4 {
        return Err(Error::PycHeaderShort {
            need: 4,
            got: bytes.len(),
        });
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let version: PyVersion = pyversion_from_magic(magic).ok_or(Error::UnknownPycMagic { magic })?;
    let header_len: usize = version.pyc_header_len();
    if bytes.len() < header_len {
        return Err(Error::PycHeaderShort {
            need: header_len,
            got: bytes.len(),
        });
    }

    let (bit_field, timestamp, source_size): (Option<u32>, u32, Option<u32>) =
        if version.has_pep552_header() {
            let bf: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let ts: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let ss: u32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
            (Some(bf), ts, Some(ss))
        } else if version.has_source_size() {
            let ts: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let ss: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            (None, ts, Some(ss))
        } else {
            let ts: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            (None, ts, None)
        };

    let header: PycHeader = PycHeader {
        version,
        magic,
        bit_field,
        timestamp,
        source_size,
    };

    let code: Object = crate::reader::load(&bytes[header_len..], version)?;
    Ok(PycFile { header, code })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::object::{CodeEra, CodeObject};

    fn empty_code(era: CodeEra) -> CodeObject {
        let mut co: CodeObject = CodeObject::new(era);
        co.filename = Object::ShortAscii {
            value: "<test>".to_owned(),
            interned: false,
        };
        co.name = Object::ShortAscii {
            value: "<module>".to_owned(),
            interned: false,
        };
        co.qualname = co.name.clone();
        co
    }

    #[test]
    fn pyc_header_round_trip_312() {
        let co: CodeObject = empty_code(CodeEra::Py311Plus);
        let file: PycFile = PycFile {
            header: PycHeader::deterministic(PyVersion::PY312).unwrap(),
            code: Object::Code(Box::new(co)),
        };
        let bytes: Vec<u8> = write_pyc(&file).unwrap();
        let back: PycFile = read_pyc(&bytes).unwrap();
        assert_eq!(back.header.version, PyVersion::PY312);
        assert_eq!(back.header.bit_field, Some(0));
    }

    #[test]
    fn pyc_header_round_trip_39() {
        let co: CodeObject = empty_code(CodeEra::Py38to310);
        let file: PycFile = PycFile {
            header: PycHeader::deterministic(PyVersion::PY39).unwrap(),
            code: Object::Code(Box::new(co)),
        };
        let bytes: Vec<u8> = write_pyc(&file).unwrap();
        let back: PycFile = read_pyc(&bytes).unwrap();
        assert_eq!(back.header.version, PyVersion::PY39);
        assert_eq!(back.header.bit_field, Some(0));
    }

    #[test]
    fn pyc_header_round_trip_27() {
        let co: CodeObject = empty_code(CodeEra::Py27);
        let file: PycFile = PycFile {
            header: PycHeader::deterministic(PyVersion::PY27).unwrap(),
            code: Object::Code(Box::new(co)),
        };
        let bytes: Vec<u8> = write_pyc(&file).unwrap();
        let back: PycFile = read_pyc(&bytes).unwrap();
        assert_eq!(back.header.version, PyVersion::PY27);
        assert!(back.header.bit_field.is_none());
        assert!(back.header.source_size.is_none());
    }

    #[test]
    fn pyc_header_round_trip_legacy_eras() {
        for (version, era) in [
            (PyVersion::PY11, CodeEra::Py10to12),
            (PyVersion::PY14, CodeEra::Py13to14),
            (PyVersion::PY15, CodeEra::Py15to20),
            (PyVersion::PY20, CodeEra::Py15to20),
            (PyVersion::PY21, CodeEra::Py21to22),
            (PyVersion::PY27, CodeEra::Py27),
            (PyVersion::PY30, CodeEra::Py30to37),
            (PyVersion::PY32, CodeEra::Py30to37),
        ] {
            let co: CodeObject = empty_code(era);
            let file: PycFile = PycFile {
                header: PycHeader::deterministic(version).unwrap(),
                code: Object::Code(Box::new(co)),
            };
            let bytes: Vec<u8> = write_pyc(&file).unwrap();
            let back: PycFile = read_pyc(&bytes).unwrap();
            assert_eq!(back.header.version, version, "version round trip");
            assert_eq!(
                back.header.version.pyc_header_len(),
                8,
                "legacy header is 8 bytes"
            );
            assert!(back.header.bit_field.is_none());
            assert!(back.header.source_size.is_none());
        }
    }

    #[test]
    fn pyc_unknown_magic() {
        let err: Error = read_pyc(&[0xFF, 0xFF, 0x0D, 0x0A]).unwrap_err();
        assert!(matches!(err, Error::UnknownPycMagic { .. }));
    }
}
