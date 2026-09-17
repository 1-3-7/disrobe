use wasmparser::{Parser, Payload};

use crate::error::{Error, Result};

#[derive(Debug, Default, Clone)]
pub struct DwarfSections {
    pub info: Vec<u8>,
    pub abbrev: Vec<u8>,
    pub line: Vec<u8>,
    pub str_: Vec<u8>,
    pub str_offsets: Vec<u8>,
    pub line_str: Vec<u8>,
    pub ranges: Vec<u8>,
    pub rnglists: Vec<u8>,
    pub pubnames: Vec<u8>,
    pub pubtypes: Vec<u8>,
    pub addr: Vec<u8>,
    pub loc: Vec<u8>,
    pub loclists: Vec<u8>,
    pub aranges: Vec<u8>,
}

impl DwarfSections {
    #[inline]
    #[must_use]
    pub const fn has_any(&self) -> bool {
        !self.info.is_empty() || !self.line.is_empty()
    }

    #[inline]
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.has_any()
    }

    #[inline]
    #[must_use]
    pub const fn total_bytes(&self) -> usize {
        self.info.len()
            + self.abbrev.len()
            + self.line.len()
            + self.str_.len()
            + self.str_offsets.len()
            + self.line_str.len()
            + self.ranges.len()
            + self.rnglists.len()
            + self.pubnames.len()
            + self.pubtypes.len()
            + self.addr.len()
            + self.loc.len()
            + self.loclists.len()
            + self.aranges.len()
    }
}

pub fn extract(input: &[u8]) -> Result<DwarfSections> {
    let mut out: DwarfSections = DwarfSections::default();
    for payload in Parser::new(0).parse_all(input) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(format!("{e}")))?;
        if let Payload::CustomSection(reader) = payload {
            let name: &str = reader.name();
            let data: Vec<u8> = reader.data().to_vec();
            match name {
                ".debug_info" => out.info = data,
                ".debug_abbrev" => out.abbrev = data,
                ".debug_line" => out.line = data,
                ".debug_str" => out.str_ = data,
                ".debug_str_offsets" => out.str_offsets = data,
                ".debug_line_str" => out.line_str = data,
                ".debug_ranges" => out.ranges = data,
                ".debug_rnglists" => out.rnglists = data,
                ".debug_pubnames" => out.pubnames = data,
                ".debug_pubtypes" => out.pubtypes = data,
                ".debug_addr" => out.addr = data,
                ".debug_loc" => out.loc = data,
                ".debug_loclists" => out.loclists = data,
                ".debug_aranges" => out.aranges = data,
                _ => {}
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const EMPTY_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    #[test]
    fn empty_module_has_no_dwarf() {
        let sections: DwarfSections = extract(EMPTY_WASM).unwrap();
        assert!(sections.is_empty());
        assert_eq!(sections.total_bytes(), 0);
    }

    #[test]
    fn extracts_debug_info_custom_section() {
        let mut bytes: Vec<u8> = Vec::from(EMPTY_WASM);
        let section_name: &str = ".debug_info";
        let name_len: u8 = u8::try_from(section_name.len()).unwrap();
        let mut payload: Vec<u8> = Vec::new();
        payload.push(name_len);
        payload.extend_from_slice(section_name.as_bytes());
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let payload_len: u8 = u8::try_from(payload.len()).unwrap();
        bytes.push(0x00);
        bytes.push(payload_len);
        bytes.extend_from_slice(&payload);
        let sections: DwarfSections = extract(&bytes).unwrap();
        assert_eq!(sections.info, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(sections.has_any());
    }
}
