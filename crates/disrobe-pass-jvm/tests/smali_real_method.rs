#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]
use disrobe_pass_jvm::disassemble_dalvik;

const HELLO_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/Hello.dex");

#[inline]
fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

#[inline]
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn uleb(b: &[u8], o: usize) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut cursor: usize = o;
    loop {
        let byte: u8 = b[cursor];
        cursor += 1;
        result |= u32::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (result, cursor)
}

fn code_unit_slice(b: &[u8], code_off: usize) -> Vec<u16> {
    let insns_size: usize = u32_at(b, code_off + 12) as usize;
    let insns_off: usize = code_off + 16;
    let mut units: Vec<u16> = Vec::with_capacity(insns_size);
    for k in 0..insns_size {
        units.push(u16_at(b, insns_off + k * 2));
    }
    units
}

fn skip_encoded_fields(b: &[u8], mut o: usize, count: u32) -> usize {
    for _ in 0..count {
        let (_field_idx_diff, n1): (u32, usize) = uleb(b, o);
        let (_access_flags, n2): (u32, usize) = uleb(b, n1);
        o = n2;
    }
    o
}

fn collect_method_code_offsets(b: &[u8], mut o: usize, count: u32, out: &mut Vec<usize>) -> usize {
    for _ in 0..count {
        let (_method_idx_diff, n1): (u32, usize) = uleb(b, o);
        let (_access_flags, n2): (u32, usize) = uleb(b, n1);
        let (code_off, n3): (u32, usize) = uleb(b, n2);
        if code_off != 0 {
            out.push(code_off as usize);
        }
        o = n3;
    }
    o
}

fn all_code_offsets(b: &[u8]) -> Vec<usize> {
    let class_defs_size: u32 = u32_at(b, 96);
    let class_defs_off: usize = u32_at(b, 100) as usize;
    let mut offsets: Vec<usize> = Vec::new();
    for ci in 0..class_defs_size as usize {
        let base: usize = class_defs_off + ci * 32;
        let class_data_off: usize = u32_at(b, base + 24) as usize;
        if class_data_off == 0 {
            continue;
        }
        let (static_fields, n1): (u32, usize) = uleb(b, class_data_off);
        let (instance_fields, n2): (u32, usize) = uleb(b, n1);
        let (direct_methods, n3): (u32, usize) = uleb(b, n2);
        let (virtual_methods, n4): (u32, usize) = uleb(b, n3);
        let after_static: usize = skip_encoded_fields(b, n4, static_fields);
        let after_instance: usize = skip_encoded_fields(b, after_static, instance_fields);
        let after_direct: usize =
            collect_method_code_offsets(b, after_instance, direct_methods, &mut offsets);
        let _after_virtual: usize =
            collect_method_code_offsets(b, after_direct, virtual_methods, &mut offsets);
    }
    offsets
}

fn emit_method_smali(units: &[u16]) -> String {
    use std::fmt::Write as _;
    let decoded: Vec<(u32, &'static str)> = disassemble_dalvik(units);
    let mut body: String = String::with_capacity(decoded.len() * 24);
    let _ = writeln!(body, ".method <recovered>()V");
    for (offset, mnemonic) in &decoded {
        let _ = writeln!(body, "    {offset:#06x}: {mnemonic}");
    }
    let _ = writeln!(body, ".end method");
    body
}

#[test]
fn disassembles_real_dex_method_to_concrete_mnemonics() {
    assert_eq!(&HELLO_DEX[..4], b"dex\n", "fixture is a real DEX");
    let offsets: Vec<usize> = all_code_offsets(HELLO_DEX);
    assert!(
        !offsets.is_empty(),
        "walked real class_data to at least one code_item"
    );

    let mut all_mnemonics: std::collections::BTreeSet<&'static str> =
        std::collections::BTreeSet::new();
    let mut richest_body: String = String::new();
    let mut richest_len: usize = 0;
    for code_off in &offsets {
        let units: Vec<u16> = code_unit_slice(HELLO_DEX, *code_off);
        if units.len() > richest_len {
            richest_len = units.len();
            richest_body = emit_method_smali(&units);
        }
        for (_off, mnemonic) in disassemble_dalvik(&units) {
            all_mnemonics.insert(mnemonic);
        }
    }

    assert!(
        richest_body.contains(".method") && richest_body.contains(".end method"),
        "emitted a real smali method shell"
    );
    for expected in [
        "new-instance",
        "const-string",
        "invoke-direct",
        "invoke-virtual",
        "sget-object",
        "move-result-object",
        "return-void",
    ] {
        assert!(
            all_mnemonics.contains(expected),
            "in-house decoder recovered `{expected}` from real Hello.dex; got {all_mnemonics:?}"
        );
    }
    assert!(
        all_mnemonics.contains("return-object") || all_mnemonics.contains("return"),
        "recovered a return-family opcode"
    );
    assert!(
        all_mnemonics.len() >= 8,
        "recovered a non-trivial instruction vocabulary, got {}",
        all_mnemonics.len()
    );
}

#[test]
fn smallest_real_method_is_init_invoke_direct_return_void() {
    let offsets: Vec<usize> = all_code_offsets(HELLO_DEX);
    let init_units: Vec<u16> = offsets
        .iter()
        .map(|o| code_unit_slice(HELLO_DEX, *o))
        .find(|u| u.len() == 4)
        .expect("Greeter.<init> code_item with 4 units");
    let decoded: Vec<&'static str> = disassemble_dalvik(&init_units)
        .into_iter()
        .map(|(_, m)| m)
        .collect();
    assert_eq!(
        decoded,
        vec!["invoke-direct", "return-void"],
        "real <init> decodes exactly to invoke-direct/return-void"
    );
}
