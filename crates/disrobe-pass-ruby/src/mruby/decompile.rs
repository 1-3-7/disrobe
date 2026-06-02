use serde::{Deserialize, Serialize};

use crate::mruby::irep::IrepTree;
use crate::mruby::lift::lift_tree;
use crate::mruby::reader::RiteBinary;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MrubyDecompiled {
    pub source: String,
    pub irep_count: u32,
    pub instruction_count: u32,
    pub has_body: bool,
    pub has_debug_info: bool,
    pub has_local_var_names: bool,
    pub recovered_symbols: Vec<String>,
    pub recovered_strings: Vec<String>,
}

#[must_use]
pub fn decompile(r: &RiteBinary, irep: Option<&IrepTree>) -> MrubyDecompiled {
    use core::fmt::Write as _;
    let mut s: String = String::with_capacity(1024);
    s.push_str("# mruby decompile (clean-room RITE/IREP recovery)\n");
    let _: core::result::Result<(), core::fmt::Error> = writeln!(
        s,
        "# format: {} compiler: {}/{}",
        ascii_or_hex(r.header.format_version),
        ascii_or_hex(r.header.compiler_name),
        ascii_or_hex(r.header.compiler_version),
    );

    let mut recovered_symbols: Vec<String> = Vec::new();
    let mut recovered_strings: Vec<String> = Vec::new();
    let mut instruction_count: u32 = 0;
    let mut has_body: bool = false;

    match irep {
        Some(tree) => {
            let _: core::result::Result<(), core::fmt::Error> = writeln!(
                s,
                "# irep records: {} | iseq bytes: {} | pool: {} | syms: {}",
                tree.records.len(),
                tree.total_insn_bytes,
                tree.total_pool_entries,
                tree.total_symbols,
            );
            for rec in &tree.records {
                for sym in &rec.symbols {
                    if !sym.is_empty() {
                        recovered_symbols.push(sym.clone());
                    }
                }
                for entry in &rec.pool {
                    if let Some(v) = entry.value.as_ref() {
                        recovered_strings.push(v.clone());
                    }
                }
            }

            match lift_tree(tree) {
                Ok(body) => {
                    instruction_count = tree.total_insn_bytes;
                    has_body = !body.trim().is_empty();
                    s.push_str("# --- reconstructed source ---\n");
                    if has_body {
                        s.push_str(&body);
                    } else {
                        s.push_str(
                            "# (empty body: top-level iseq carried no emitted statements)\n",
                        );
                    }
                }
                Err(e) => {
                    let _: core::result::Result<(), core::fmt::Error> =
                        writeln!(s, "# iseq lift failed: {e}");
                }
            }
        }
        None => {
            let _: core::result::Result<(), core::fmt::Error> =
                writeln!(s, "# irep section count: {} (body unparsed)", r.irep_count);
        }
    }

    if !recovered_symbols.is_empty() {
        s.push_str("# symbols:\n");
        for sym in &recovered_symbols {
            let _: core::result::Result<(), core::fmt::Error> = writeln!(s, "#   :{sym}");
        }
    }
    if !recovered_strings.is_empty() {
        s.push_str("# string/pool literals:\n");
        for lit in &recovered_strings {
            let _: core::result::Result<(), core::fmt::Error> = writeln!(s, "#   {lit:?}");
        }
    }
    if r.has_debug {
        s.push_str("# DBG section present: line numbers recoverable\n");
    }
    if r.has_lvar {
        s.push_str("# LVAR section present: local variable names recoverable\n");
    }

    let irep_count: u32 = irep.map_or(r.irep_count, |t| {
        u32::try_from(t.records.len()).unwrap_or(u32::MAX)
    });

    MrubyDecompiled {
        source: s,
        irep_count,
        instruction_count,
        has_body,
        has_debug_info: r.has_debug,
        has_local_var_names: r.has_lvar,
        recovered_symbols,
        recovered_strings,
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
    fn decompiles_structure_without_irep_body() {
        let bytes: Vec<u8> = synth();
        let r: RiteBinary = read_rite(&bytes).expect("rite");
        let out: MrubyDecompiled = decompile(&r, None);
        assert!(out.source.contains("body unparsed"));
        assert!(out.has_debug_info);
        assert_eq!(out.irep_count, 1);
        assert!(!out.has_body);
        assert!(out.recovered_symbols.is_empty());
    }

    #[test]
    fn decompiles_with_recovered_irep_symbols_and_body() {
        use crate::mruby::irep::{IrepRecord, IrepTree, PoolEntry, PoolKind};
        let bytes: Vec<u8> = synth();
        let r: RiteBinary = read_rite(&bytes).expect("rite");
        let iseq: Vec<u8> = vec![
            0x12, 0x01, 0x51, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x01, 0x38, 0x01,
        ];
        let tree: IrepTree = IrepTree {
            records: vec![IrepRecord {
                depth: 0,
                index: 0,
                nlocals: 1,
                nregs: 4,
                child_count: 0,
                catch_count: 0,
                insn_len: u32::try_from(iseq.len()).expect("fits"),
                iseq,
                pool: vec![PoolEntry {
                    kind: PoolKind::String,
                    value: Some("hi".to_owned()),
                }],
                symbols: vec!["puts".to_owned()],
                child_indices: vec![],
            }],
            total_insn_bytes: 11,
            total_symbols: 1,
            total_pool_entries: 1,
        };
        let out: MrubyDecompiled = decompile(&r, Some(&tree));
        assert!(out.recovered_symbols.contains(&"puts".to_owned()));
        assert!(out.recovered_strings.contains(&"hi".to_owned()));
        assert!(out.source.contains(":puts"));
        assert!(out.source.contains("irep records: 1"));
        assert!(out.has_body);
        assert!(
            out.source.contains("puts(\"hi\")"),
            "source: {}",
            out.source
        );
    }
}
