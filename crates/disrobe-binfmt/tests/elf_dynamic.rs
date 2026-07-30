#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use disrobe_binfmt::{ElfDynamic, NativeFile, parse_elf_dynamic, parse_native};

use common::requirement::{required_corpus, required_fixture};

const NIM_ELF: &str = "native/nim/hello.nim.elf";

const PYARMOR_RUNTIME: &str =
    "python/pyarmor/v9/platform_linux/pyarmor_runtime_000000/pyarmor_runtime.so";

#[test]
fn crafted_so_matches_readelf_ground_truth() {
    let bytes: Vec<u8> = required_fixture("elf-dynamic", "sample.elf");

    let dynamic: ElfDynamic = parse_elf_dynamic(&bytes).expect("dynamic segment parses");

    assert_eq!(
        dynamic.needed,
        vec!["libc.so.6".to_owned(), "libm.so.6".to_owned()],
        "DT_NEEDED must match `readelf -d` (libc.so.6, libm.so.6)"
    );
    assert_eq!(
        dynamic.soname.as_deref(),
        Some("libsample.so.1"),
        "DT_SONAME must match `readelf -d`"
    );
    assert_eq!(
        dynamic.rpath.as_deref(),
        Some("/opt/legacy/lib"),
        "DT_RPATH must match `readelf -d`"
    );
    assert_eq!(
        dynamic.runpath.as_deref(),
        Some("$ORIGIN/../lib:/usr/local/sample/lib"),
        "DT_RUNPATH must match `readelf -d`"
    );
    assert_eq!(
        dynamic.entry_count, 8,
        "8 dynamic entries up to and including DT_NULL, per `readelf -d`"
    );
}

#[test]
fn declared_string_table_crossing_load_boundary_rejects() {
    let mut bytes: Vec<u8> = required_fixture("elf-dynamic", "sample.elf");
    let strsz_tag_offset: usize = 0x170;
    let strsz_value_offset: usize = 0x178;
    let strsz_value_end: usize = strsz_value_offset
        .checked_add(8)
        .expect("string table size field should fit");
    let strsz_tag: u64 = disrobe_bytes::read_u64_le_at(&bytes, strsz_tag_offset)
        .expect("string table tag should parse");
    let oversized: [u8; 8] = 0xe1u64.to_le_bytes();
    let field: &mut [u8] = bytes
        .get_mut(strsz_value_offset..strsz_value_end)
        .expect("string table size field should exist");

    assert_eq!(strsz_tag, 10);
    field.copy_from_slice(&oversized);
    assert!(parse_elf_dynamic(&bytes).is_none());
}

#[test]
fn real_elf_dynamic_surfaced_through_native_file() {
    let bytes: Vec<u8> = required_corpus(NIM_ELF);
    let nf: NativeFile = parse_native(&bytes).expect("parse native elf");
    let dynamic: &ElfDynamic = nf
        .dynamic
        .as_ref()
        .expect("native file surfaces the dynamic segment for a dynamically linked elf");
    assert_eq!(
        dynamic.needed,
        vec![
            "libpthread.so.0".to_owned(),
            "libc.so.6".to_owned(),
            "ld-linux-x86-64.so.2".to_owned(),
        ],
        "the surfaced DT_NEEDED must match `readelf -d`"
    );
}

#[test]
fn real_nim_executable_needed_matches_readelf() {
    let bytes: Vec<u8> = required_corpus(NIM_ELF);
    let dynamic: ElfDynamic = parse_elf_dynamic(&bytes).expect("nim elf has a dynamic segment");
    assert_eq!(
        dynamic.needed,
        vec![
            "libpthread.so.0".to_owned(),
            "libc.so.6".to_owned(),
            "ld-linux-x86-64.so.2".to_owned(),
        ],
        "DT_NEEDED of the real nim binary must match `readelf -d`"
    );
    assert!(
        dynamic.soname.is_none(),
        "the nim executable carries no DT_SONAME, per `readelf -d`"
    );
}

#[test]
fn real_pyarmor_runtime_needed_matches_readelf() {
    let bytes: Vec<u8> = required_corpus(PYARMOR_RUNTIME);
    let dynamic: ElfDynamic =
        parse_elf_dynamic(&bytes).expect("pyarmor runtime has a dynamic segment");
    assert_eq!(
        dynamic.needed,
        vec![
            "libpthread.so.0".to_owned(),
            "libdl.so.2".to_owned(),
            "libc.so.6".to_owned(),
        ],
        "DT_NEEDED of the real pyarmor runtime must match `readelf -d`"
    );
}

#[test]
fn statically_shaped_input_has_no_dynamic() {
    let mut buf: Vec<u8> = vec![0u8; 0x80];
    buf[0..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    buf[4] = 2;
    buf[5] = 1;
    assert!(
        parse_elf_dynamic(&buf).is_none(),
        "no program headers means no dynamic segment"
    );
}
