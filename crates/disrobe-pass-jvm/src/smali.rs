use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::dex::DexFile;
use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmaliEmission {
    pub class_count: usize,
    pub text: String,
    pub lossy_notes: Vec<String>,
}

pub fn emit(dex: &DexFile) -> Result<SmaliEmission> {
    if dex.class_descriptors.is_empty() && !dex.strings.is_empty() {
        return Err(Error::SmaliLossy(
            "dex has strings but no class defs — emission would lose data",
        ));
    }
    let mut text: String = String::with_capacity(dex.class_descriptors.len() * 64);
    let mut lossy: Vec<String> = Vec::new();
    for descriptor in &dex.class_descriptors {
        let _ = writeln!(text, ".class {descriptor}");
        let _ = writeln!(text, ".super Ljava/lang/Object;");
        let _ = writeln!(text);
    }
    if dex.header.class_defs_size as usize != dex.class_descriptors.len() {
        lossy.push(format!(
            "header claims {} class defs but parser yielded {}",
            dex.header.class_defs_size,
            dex.class_descriptors.len()
        ));
    }
    Ok(SmaliEmission {
        class_count: dex.class_descriptors.len(),
        text,
        lossy_notes: lossy,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::dex::{DexHeader, DexVersion};

    fn empty_dex() -> DexFile {
        DexFile {
            header: DexHeader {
                version: DexVersion::V035,
                checksum: 0,
                signature: [0u8; 20],
                file_size: 0,
                header_size: 0x70,
                endian_tag: crate::dex::DEX_ENDIAN_TAG,
                link_size: 0,
                link_off: 0,
                map_off: 0,
                string_ids_size: 0,
                string_ids_off: 0,
                type_ids_size: 0,
                type_ids_off: 0,
                proto_ids_size: 0,
                proto_ids_off: 0,
                field_ids_size: 0,
                field_ids_off: 0,
                method_ids_size: 0,
                method_ids_off: 0,
                class_defs_size: 0,
                class_defs_off: 0,
                data_size: 0,
                data_off: 0,
            },
            strings: Vec::new(),
            type_names: Vec::new(),
            class_descriptors: Vec::new(),
        }
    }

    #[test]
    fn empty_dex_emits_empty_string() {
        let d: DexFile = empty_dex();
        let s: SmaliEmission = emit(&d).expect("ok");
        assert_eq!(s.class_count, 0);
        assert!(s.text.is_empty());
    }

    #[test]
    fn classes_emit_directives() {
        let mut d: DexFile = empty_dex();
        d.class_descriptors.push("Lcom/example/Foo;".into());
        d.header.class_defs_size = 1;
        let s: SmaliEmission = emit(&d).expect("ok");
        assert!(s.text.contains(".class Lcom/example/Foo;"));
    }
}
