use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::dalvik::{DalvikInsn, InsnFormat, decode_method};
use crate::dex::{CodeItem, DexFile, TryItem};
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
            "dex has strings but no class defs - emission would lose data",
        ));
    }
    let mut text: String = String::with_capacity(dex.class_descriptors.len() * 128);
    let mut lossy: Vec<String> = Vec::new();
    for descriptor in &dex.class_descriptors {
        let _ = writeln!(text, ".class {descriptor}");
        let _ = writeln!(text, ".super Ljava/lang/Object;");
        for field in dex.field_ids.iter().filter(|f| &f.class == descriptor) {
            let _ = writeln!(text, ".field {}:{}", field.name, field.type_name);
        }
        for method in dex.method_ids.iter().filter(|m| &m.class == descriptor) {
            let params: String = method.proto.parameters.concat();
            let _ = writeln!(
                text,
                ".method {}({}){}",
                method.name, params, method.proto.return_type
            );
            let _ = writeln!(text, ".end method");
        }
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

#[must_use]
pub fn emit_method_body(item: &CodeItem) -> String {
    let insns: Vec<DalvikInsn> = decode_method(&item.insns);
    emit_method_body_from_insns(
        &item.method_name,
        &item.method_descriptor,
        item.is_direct,
        item.registers_size,
        &insns,
        &item.tries,
    )
}

#[must_use]
pub fn emit_method_body_from_insns(
    name: &str,
    descriptor: &str,
    is_direct: bool,
    registers_size: u16,
    insns: &[DalvikInsn],
    tries: &[TryItem],
) -> String {
    let mut labels: BTreeSet<u32> = BTreeSet::new();
    for insn in insns {
        if let Some(t) = insn.branch_target_pc() {
            labels.insert(t);
        }
    }
    for t in tries {
        labels.insert(t.start_addr);
        labels.insert(t.start_addr + u32::from(t.insn_count));
        for (_, addr) in &t.handlers {
            labels.insert(*addr);
        }
        if let Some(addr) = t.catch_all {
            labels.insert(addr);
        }
    }

    let mut out: String = String::with_capacity(insns.len() * 32);
    let kind: &str = if is_direct { "direct" } else { "virtual" };
    let _ = writeln!(out, ".method {kind} {name}{descriptor}");
    let _ = writeln!(out, "    .registers {registers_size}");
    for t in tries {
        let try_end: u32 = t.start_addr + u32::from(t.insn_count);
        for (catch_type, addr) in &t.handlers {
            let ty: &str = catch_type.as_deref().unwrap_or("Ljava/lang/Throwable;");
            let _ = writeln!(
                out,
                "    .catch {ty} {{:label_{:x} .. :label_{:x}}} :label_{:x}",
                t.start_addr, try_end, addr
            );
        }
        if let Some(addr) = t.catch_all {
            let _ = writeln!(
                out,
                "    .catchall {{:label_{:x} .. :label_{:x}}} :label_{:x}",
                t.start_addr, try_end, addr
            );
        }
    }
    for insn in insns {
        if labels.contains(&insn.pc) {
            let _ = writeln!(out, "    :label_{:x}", insn.pc);
        }
        let _ = writeln!(out, "    {}", render_insn(insn, &labels));
    }
    let _ = writeln!(out, ".end method");
    out
}

fn render_insn(insn: &DalvikInsn, _labels: &BTreeSet<u32>) -> String {
    let mnemonic: &str = insn.mnemonic;
    let regs: String = insn
        .regs
        .iter()
        .map(|r: &u16| format!("v{r}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut tail: String = String::new();
    if let Some(target) = insn.branch_target_pc() {
        if !tail.is_empty() {
            tail.push_str(", ");
        }
        let _ = write!(tail, ":label_{target:x}");
    } else if let Some(lit) = insn.literal {
        let _ = write!(tail, "{lit}");
    } else if let Some(idx) = insn.index {
        let _ = write!(tail, "@{idx}");
    }
    match (regs.is_empty(), tail.is_empty()) {
        (true, true) => mnemonic.to_owned(),
        (false, true) => format!("{mnemonic} {regs}"),
        (true, false) => format!("{mnemonic} {tail}"),
        (false, false) => match insn.format {
            InsnFormat::Fmt35c
            | InsnFormat::Fmt3rc
            | InsnFormat::Fmt35mi
            | InsnFormat::Fmt35ms
            | InsnFormat::Fmt3rmi
            | InsnFormat::Fmt3rms
            | InsnFormat::Fmt45cc
            | InsnFormat::Fmt4rcc => format!("{mnemonic} {{{regs}}}, {tail}"),
            _ => format!("{mnemonic} {regs}, {tail}"),
        },
    }
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
            class_super_descriptors: std::collections::BTreeMap::new(),
            proto_ids: Vec::new(),
            field_ids: Vec::new(),
            method_ids: Vec::new(),
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
