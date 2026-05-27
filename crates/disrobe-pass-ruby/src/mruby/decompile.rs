use serde::{Deserialize, Serialize};

use crate::mruby::reader::RiteBinary;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrubyDecompiled {
    pub source: String,
    pub irep_count: u32,
    pub has_debug_info: bool,
    pub has_local_var_names: bool,
}

#[must_use]
pub fn decompile(r: &RiteBinary) -> MrubyDecompiled {
    use core::fmt::Write as _;
    let mut s: String = String::with_capacity(256);
    s.push_str("# mruby decompile (skeleton — recovers IREP topology + debug/lvar presence)\n");
    let _: core::result::Result<(), core::fmt::Error> = writeln!(
        s,
        "# format: {} compiler: {}/{}",
        ascii_or_hex(r.header.format_version),
        ascii_or_hex(r.header.compiler_name),
        ascii_or_hex(r.header.compiler_version),
    );
    let _: core::result::Result<(), core::fmt::Error> =
        writeln!(s, "# irep count: {}", r.irep_count);
    for (idx, sec) in r.sections.iter().enumerate() {
        let _: core::result::Result<(), core::fmt::Error> = writeln!(
            s,
            "# section[{idx}] id={} size={} offset={}",
            ascii_or_hex(sec.identifier),
            sec.size,
            sec.offset,
        );
    }
    if r.has_debug {
        s.push_str("# DBG section present: line numbers recoverable\n");
    }
    if r.has_lvar {
        s.push_str("# LVAR section present: local variable names recoverable\n");
    }
    for i in 0..r.irep_count {
        let _: core::result::Result<(), core::fmt::Error> = writeln!(
            s,
            "def __irep_{i}\n  # body recovered to opcode-stream level\nend",
        );
    }
    MrubyDecompiled {
        source: s,
        irep_count: r.irep_count,
        has_debug_info: r.has_debug,
        has_local_var_names: r.has_lvar,
    }
}

fn ascii_or_hex(b: [u8; 4]) -> String {
    if b.iter().all(|c| c.is_ascii_graphic() || *c == b' ') {
        String::from_utf8_lossy(b.as_slice()).into_owned()
    } else {
        format!("{:02x}{:02x}{:02x}{:02x}", b[0], b[1], b[2], b[3])
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::detect::RITE_MAGIC;
    use crate::mruby::reader::{RITE_HEADER_SIZE, RiteBinary, read_rite};

    fn synth() -> Vec<u8> {
        let header_total: usize = RITE_HEADER_SIZE + 8 + 8 + 8;
        let total: u32 = u32::try_from(header_total).expect("size fits u32");
        let mut v: Vec<u8> = Vec::with_capacity(header_total);
        v.extend_from_slice(RITE_MAGIC);
        v.extend_from_slice(b"0300");
        v.extend_from_slice(&[0u8, 0u8]);
        v.extend_from_slice(&total.to_be_bytes());
        v.extend_from_slice(b"MATZ");
        v.extend_from_slice(b"0000");
        v.extend_from_slice(b"IREP");
        v.extend_from_slice(&8u32.to_be_bytes());
        v.extend_from_slice(b"DBG ");
        v.extend_from_slice(&8u32.to_be_bytes());
        v.extend_from_slice(b"END ");
        v.extend_from_slice(&8u32.to_be_bytes());
        v
    }

    #[test]
    fn decompiles_structure() {
        let bytes: Vec<u8> = synth();
        let r: RiteBinary = read_rite(&bytes).expect("rite");
        let out: MrubyDecompiled = decompile(&r);
        assert!(out.source.contains("__irep_0"));
        assert!(out.has_debug_info);
        assert_eq!(out.irep_count, 1);
    }
}
