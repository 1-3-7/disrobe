#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_binfmt::containers::unityfs;
use disrobe_pass_lua::obfuscator::slua::{self, SluaCompression, SluaParams};
use disrobe_pass_lua::reader::common::{LuaChunk, LuaConstant, LuaDialect, LuaProto};
use disrobe_pass_lua::{
    DecompiledChunk, DeobfOptions, PeelResult, decompile_auto, serialize_chunk,
};

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn corpus_path(rel: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("lua");
    for seg in rel.split('/') {
        p.push(seg);
    }
    p
}

fn find_lua() -> Option<String> {
    let candidates: [&str; 6] = ["lua", "lua5.4", "lua5.1", "luajit", "lua54", "lua51"];
    for c in candidates {
        if Command::new(c)
            .arg("-v")
            .output()
            .is_ok_and(|o| o.status.success() || !o.stderr.is_empty())
        {
            return Some(c.to_owned());
        }
    }
    None
}

fn run_lua(interp: &str, source: &str) -> Option<String> {
    let unique: u64 = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let purpose: String = format!("slua_oracle_{}_{unique}", std::process::id());
    let (scratch, file): (disrobe_core::scratch::ScratchFile, std::fs::File) =
        disrobe_core::scratch::ScratchFile::create(&purpose, "lua").ok()?;
    drop(file);
    let tmp: PathBuf = scratch.path().to_path_buf();
    std::fs::write(&tmp, source).ok()?;
    let out = Command::new(interp).arg(&tmp).output().ok()?;
    if !out.status.success() {
        eprintln!("lua run failed: {}", String::from_utf8_lossy(&out.stderr));
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).replace("\r\n", "\n"))
}

fn runnable_from_decompiled(source: &str) -> String {
    let mut body: String = String::with_capacity(source.len() + 16);
    for line in source.lines() {
        if line.trim_start().starts_with("--") {
            continue;
        }
        body.push_str(line);
        body.push('\n');
    }
    body.push_str("_main()\n");
    body
}

fn ground_truth_chunk() -> LuaChunk {
    let main: LuaProto = LuaProto {
        source: Some("@hello.lua".to_owned()),
        line_defined: 0,
        last_line_defined: 0,
        num_params: 0,
        is_vararg: 1,
        max_stack_size: 2,
        code: vec![0x0040_0006, 0x0000_4041, 0x0100_4024, 0x0080_0026],
        constants: vec![
            LuaConstant::Str("print".to_owned()),
            LuaConstant::Str("hello from SLua deobfuscation".to_owned()),
        ],
        protos: Vec::new(),
        source_lines: vec![1, 1, 1, 1],
        locals: Vec::new(),
        upvalues: vec![disrobe_pass_lua::reader::common::LuaUpvalueName {
            name: "_ENV".to_owned(),
        }],
    };
    LuaChunk {
        dialect: LuaDialect::Lua53,
        version_byte: 0x53,
        format: 0,
        little_endian: true,
        size_of_int: 4,
        size_of_size_t: 8,
        size_of_instruction: 4,
        size_of_lua_integer: 8,
        size_of_lua_number: 8,
        integral_number: false,
        main,
    }
}

fn title_params() -> SluaParams {
    SluaParams::seed_derived(0xC0FF_EE12_3456_789A)
}

#[test]
fn unityfs_slua_full_chain_recovers_ground_truth() {
    let chunk: LuaChunk = ground_truth_chunk();
    let clean_bytecode: Vec<u8> = serialize_chunk(&chunk).expect("serialize ground truth");
    let reparsed_truth: LuaChunk =
        disrobe_pass_lua::reader::lua53::read(&clean_bytecode).expect("ground truth is valid 5.3");

    let params: SluaParams = title_params();
    let slua_payload: Vec<u8> = slua::build_archive(
        &params,
        true,
        SluaCompression::Zlib,
        &[("main".to_owned(), clean_bytecode.clone())],
    )
    .expect("build slua archive");

    let serialized: Vec<u8> = unityfs::build_serialized_textasset("GameLogic", &slua_payload);
    let bundle: Vec<u8> = unityfs::build_bundle_uncompressed("CAB-game", &serialized);

    let detected: Option<disrobe_binfmt::ContainerKind> = disrobe_binfmt::detect_container(&bundle);
    assert_eq!(detected, Some(disrobe_binfmt::ContainerKind::UnityFs));

    let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(disrobe_binfmt::ContainerKind::UnityFs, &bundle, temp.path())
            .expect("extract unity bundle");

    let carved_textasset: Vec<u8> = result
        .entries
        .iter()
        .find_map(|entry: &disrobe_binfmt::ExtractedEntry| {
            let path: &std::path::Path = entry.disk_path.as_deref()?;
            if entry.name.contains("TextAsset") {
                std::fs::read(path).ok()
            } else {
                None
            }
        })
        .expect("a TextAsset payload was carved from the bundle");
    assert_eq!(
        carved_textasset, slua_payload,
        "the TextAsset bytes carved by disrobe must equal the authored SLua payload"
    );

    let peel: PeelResult =
        slua::peel(&carved_textasset, &DeobfOptions::default()).expect("slua peel");
    assert!(
        peel.fully_recovered,
        "embedded-key bundle must fully recover"
    );
    assert_eq!(
        peel.deobfuscated, clean_bytecode,
        "recovered bytecode must be byte-equivalent to the pre-obfuscation ground truth"
    );

    let recovered_chunk: LuaChunk =
        disrobe_pass_lua::reader::lua53::read(&peel.deobfuscated).expect("recovered is valid 5.3");
    assert_eq!(recovered_chunk.main.code, reparsed_truth.main.code);
    assert_eq!(
        recovered_chunk.main.constants,
        reparsed_truth.main.constants
    );

    let decompiled: DecompiledChunk = decompile_auto(&peel.deobfuscated)
        .expect("existing lua path decompiles recovered bytecode");
    assert!(
        decompiled.source.contains("print"),
        "decompiled source should reference the recovered `print` constant: {}",
        decompiled.source
    );
}

#[test]
fn slua_external_key_walls_with_needs_key_message() {
    let chunk: LuaChunk = ground_truth_chunk();
    let clean_bytecode: Vec<u8> = serialize_chunk(&chunk).expect("serialize");
    let params: SluaParams = title_params();
    let slua_payload: Vec<u8> = slua::build_archive(
        &params,
        false,
        SluaCompression::None,
        &[("main".to_owned(), clean_bytecode)],
    )
    .expect("build slua archive (external key)");

    let serialized: Vec<u8> = unityfs::build_serialized_textasset("GameLogic", &slua_payload);
    let bundle: Vec<u8> = unityfs::build_bundle_uncompressed("CAB-game", &serialized);

    let temp: tempfile::TempDir = tempfile::tempdir().expect("tempdir");
    let result: disrobe_binfmt::ExtractionResult =
        disrobe_binfmt::extract_to(disrobe_binfmt::ContainerKind::UnityFs, &bundle, temp.path())
            .expect("extract");
    let carved: Vec<u8> = result
        .entries
        .iter()
        .find_map(|entry: &disrobe_binfmt::ExtractedEntry| {
            let path: &std::path::Path = entry.disk_path.as_deref()?;
            if entry.name.contains("TextAsset") {
                std::fs::read(path).ok()
            } else {
                None
            }
        })
        .expect("TextAsset carved");

    let peel: PeelResult = slua::peel(&carved, &DeobfOptions::default()).expect("peel");
    assert!(!peel.fully_recovered);
    assert!(peel.deobfuscated.is_empty());
    assert!(
        peel.residual_markers
            .iter()
            .any(|m: &String| m.contains("external") && m.contains("key")),
        "external-key bundle must report needing the game key: {:?}",
        peel.residual_markers
    );
}

#[test]
fn slua_recovered_bytecode_executes_like_original_under_real_lua() {
    let clean_bytecode: Vec<u8> = std::fs::read(corpus_path("luac/hello.5_1.luac"))
        .expect("real hello.5_1.luac fixture must be tracked");

    let original_source: DecompiledChunk =
        decompile_auto(&clean_bytecode).expect("decompile original 5.1 bytecode");

    let params: SluaParams = SluaParams::seed_derived_for(LuaDialect::Lua51, 0xABCD_1234_5678);
    let bundle: Vec<u8> = slua::build_archive(
        &params,
        true,
        SluaCompression::Zlib,
        &[("main".to_owned(), clean_bytecode.clone())],
    )
    .expect("build slua 5.1 archive from real luac");

    assert!(
        slua::detect(&bundle).is_some(),
        "authored archive must detect"
    );
    let peel: PeelResult = slua::peel(&bundle, &DeobfOptions::default()).expect("slua peel");
    assert!(
        peel.fully_recovered,
        "embedded-key archive must fully recover; markers {:?}",
        peel.residual_markers
    );
    assert_eq!(
        peel.deobfuscated, clean_bytecode,
        "recovered bytecode must be byte-equivalent to the pre-obfuscation real luac"
    );

    let recovered_source: DecompiledChunk =
        decompile_auto(&peel.deobfuscated).expect("decompile recovered bytecode");

    let Some(interp): Option<String> = find_lua() else {
        eprintln!("no lua interpreter on PATH; skipping slua execution oracle");
        return;
    };
    let expected: String = run_lua(&interp, &runnable_from_decompiled(&original_source.source))
        .expect("original decompiled source runs under real lua");
    let actual: String = run_lua(&interp, &runnable_from_decompiled(&recovered_source.source))
        .expect("recovered decompiled source runs under real lua");
    assert_eq!(
        actual.trim_end(),
        expected.trim_end(),
        "slua: recovered program output must match the original under {interp}\n--- recovered ---\n{}",
        recovered_source.source
    );
    assert_eq!(actual.trim_end(), "hello world");
}
