#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::{Cursor, Write};

use disrobe_pass_jvm::dex_builder::dexguard_native_key_sample;
use disrobe_pass_jvm::pass::{self, DexProtectorPeel, JvmSummary};
use disrobe_pass_jvm::{NativeMethod, extract_native_methods, parse_dex};
use object::write::{Object, StandardSection, Symbol, SymbolSection};
use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};

fn build_key_so(symbol: &str, key: u16) -> Vec<u8> {
    let mut obj: Object = Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let text: object::write::SectionId = obj.section_id(StandardSection::Text);
    let mov: u32 = 0x5280_0000 | (u32::from(key) << 5);
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&mov.to_le_bytes());
    body.extend_from_slice(&0xD65F_03C0u32.to_le_bytes());
    let offset: u64 = obj.append_section_data(text, body.as_slice(), 4);
    obj.add_symbol(Symbol {
        name: symbol.as_bytes().to_vec(),
        value: offset,
        size: body.len() as u64,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    obj.write().expect("write key so")
}

fn build_apk(dex: &[u8], so: &[u8]) -> Vec<u8> {
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::new());
    let mut zip: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("classes.dex", opts).expect("classes entry");
    zip.write_all(dex).expect("write dex");
    zip.start_file("lib/arm64-v8a/libdgkeys.so", opts)
        .expect("lib entry");
    zip.write_all(so).expect("write so");
    zip.finish().expect("finish zip").into_inner()
}

#[test]
fn apk_dexguard_native_key_recovery_uses_bundled_so() {
    let plaintexts: [&str; 3] = [
        "content://com.bank.app/accounts",
        "X-Device-Attestation",
        "AES/CBC/PKCS5Padding",
    ];
    let dex: Vec<u8> = dexguard_native_key_sample(&plaintexts, 0x4D);
    let parsed: disrobe_pass_jvm::DexFile = parse_dex(&dex).expect("parse dex");
    let native: NativeMethod = extract_native_methods(&parsed, &dex)
        .expect("native method scan")
        .into_iter()
        .find(|method: &NativeMethod| method.method == "nativeKey")
        .expect("native key method");
    let so: Vec<u8> = build_key_so(&native.jni_short_symbol, 0x4D);
    assert!(disrobe_binfmt::parse_native(&so).is_ok());

    let apk: Vec<u8> = build_apk(&dex, &so);
    let summary: JvmSummary = pass::analyze(&apk).expect("apk analyzes");
    let peel: DexProtectorPeel = summary
        .dex_protector_peel
        .expect("apk dex protector peel present");
    assert_eq!(peel.strings_recovered, plaintexts.len());
    assert_eq!(peel.runtime_key_walled_classes, 0);
    let recovered: Vec<String> = peel
        .recovery
        .iter()
        .flat_map(|r: &disrobe_pass_jvm::DexStringRecovery| {
            r.recovered
                .iter()
                .map(|s: &disrobe_pass_jvm::DecryptedString| s.plaintext.clone())
        })
        .collect();
    for expected in plaintexts {
        assert!(
            recovered.iter().any(|value: &String| value == expected),
            "missing {expected:?} in {recovered:?}"
        );
    }
}
