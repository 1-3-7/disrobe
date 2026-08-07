#![cfg(feature = "jvm")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]
mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{cli_binary, run_disrobe, temp_path};
use disrobe_pass_jvm::dex_builder::{ClassDef, DexBuilder, EncodedMethod, MethodRef, ProtoRef};

const JNI_REGISTER_X64_SO: &[u8] =
    include_bytes!("../../disrobe-pass-jvm/tests/fixtures/jni_register/libjnireg_x64.so");

fn corpus_jar() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus/jvm/megafile/EdgeCases-baseline.jar");
    p
}

const ACC_PUBLIC_NATIVE: u32 = 0x0001 | 0x0100;

fn native_method(class: &str, name: &str) -> EncodedMethod {
    EncodedMethod {
        tries: Vec::new(),
        method: MethodRef {
            class: class.to_owned(),
            proto: ProtoRef {
                return_type: "V".to_owned(),
                params: Vec::new(),
            },
            name: name.to_owned(),
        },
        access_flags: ACC_PUBLIC_NATIVE,
        is_direct: false,
        registers_size: 0,
        ins_size: 0,
        outs_size: 0,
        insns: Vec::new(),
        relocations: Vec::new(),
    }
}

fn build_unresolved_probe_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcom/disrobe/fixture/UnresolvedProbe;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: vec![native_method(
            "Lcom/disrobe/fixture/UnresolvedProbe;",
            "doStuff",
        )],
    });
    builder.build()
}

fn write_native_lib(dir: &Path) -> PathBuf {
    let path: PathBuf = dir.join("libjnireg_x64.so");
    std::fs::write(&path, JNI_REGISTER_X64_SO).expect("write committed .so fixture");
    path
}

#[test]
fn jni_link_human_and_json_agree_on_the_committed_registered_natives_fixture() {
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would \
         leave this case driving nothing",
        cli_binary().display()
    );
    let dex_fixture: PathBuf = {
        let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        p.pop();
        p.pop();
        p.push("corpus/jvm/dex/Hello.dex");
        p
    };
    assert!(
        dex_fixture.exists(),
        "{} is tracked in git and this case grades nothing without it",
        dex_fixture.display()
    );
    let (_scratch, so_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-human-json", "so");
    let native_path: PathBuf = so_path.parent().expect("scratch dir").to_path_buf();
    let native: PathBuf = write_native_lib(&native_path);

    let dex_str: &str = dex_fixture.to_str().expect("utf8 dex path");
    let native_str: &str = native.to_str().expect("utf8 native path");

    let human: common::Run = run_disrobe(&["jvm", "jni", dex_str, "--native", native_str]);
    assert_eq!(human.code, 0, "jvm jni text run failed: {}", human.stderr);
    let json_run: common::Run =
        run_disrobe(&["jvm", "jni", dex_str, "--native", native_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));

    let registered: &Vec<serde_json::Value> = doc["surface"]["registered_natives"]
        .as_array()
        .expect("surface.registered_natives array");
    assert_eq!(
        registered.len(),
        4,
        "the four JNINativeMethod entries recovered from the committed fixture must reach the \
         json output; got: {}",
        json_run.stdout
    );
    let names: Vec<&str> = registered
        .iter()
        .filter_map(|entry: &serde_json::Value| entry["name"].as_str())
        .collect();
    for want in ["nativeAdd", "nativeLen", "nativeNoop", "hiddenMul"] {
        assert!(
            names.contains(&want),
            "recovered RegisterNatives entries must include {want}; got {names:?}"
        );
    }

    assert!(
        human.stdout.contains("registered natives: 4"),
        "human output must state the registered natives count that the json also carries; \
         got:\n{}",
        human.stdout
    );
    for want in ["nativeAdd", "nativeLen", "nativeNoop", "hiddenMul"] {
        assert!(
            human.stdout.contains(want),
            "human output must list {want} the same way json does; got:\n{}",
            human.stdout
        );
    }

    let human_native_methods: bool = human.stdout.contains("native methods:     0");
    let json_native_method_count: u64 = doc["surface"]["native_method_count"]
        .as_u64()
        .expect("native_method_count");
    assert_eq!(
        json_native_method_count, 0,
        "Hello.dex declares no native methods, so both forms must agree on zero"
    );
    assert!(
        human_native_methods,
        "human native-method count must equal the json native_method_count of 0; got:\n{}",
        human.stdout
    );
}

#[test]
fn jni_link_reports_a_declared_native_with_no_matching_symbol_as_unresolved() {
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would \
         leave this case driving nothing",
        cli_binary().display()
    );
    let dex_bytes: Vec<u8> = build_unresolved_probe_dex();
    let (_dex_scratch, dex_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-unresolved", "dex");
    std::fs::write(&dex_path, &dex_bytes).expect("write synthetic dex");
    let native: PathBuf = write_native_lib(dex_path.parent().expect("scratch dir"));

    let dex_str: &str = dex_path.to_str().expect("utf8 dex path");
    let native_str: &str = native.to_str().expect("utf8 native path");

    let json_run: common::Run =
        run_disrobe(&["jvm", "jni", dex_str, "--native", native_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));

    assert_eq!(
        doc["surface"]["native_method_count"].as_u64(),
        Some(1),
        "the synthetic UnresolvedProbe.doStuff native method must be counted; got: {}",
        json_run.stdout
    );
    assert_eq!(
        doc["surface"]["resolved_statically"].as_u64(),
        Some(0),
        "doStuff has no matching symbol in the committed .so, which exports no Java_ symbols \
         statically, so nothing may resolve; got: {}",
        json_run.stdout
    );
    let unresolved: &Vec<serde_json::Value> = doc["unresolved"]
        .as_array()
        .expect("unresolved array in the json output");
    assert_eq!(
        unresolved.len(),
        1,
        "the unresolved native must be listed explicitly with a count, never dropped; got: {}",
        json_run.stdout
    );
    assert_eq!(
        unresolved[0]["method"].as_str(),
        Some("doStuff"),
        "the unresolved entry must name the declaring method; got: {}",
        json_run.stdout
    );

    let human: common::Run = run_disrobe(&["jvm", "jni", dex_str, "--native", native_str]);
    assert_eq!(human.code, 0, "jvm jni text run failed: {}", human.stderr);
    assert!(
        human.stdout.contains("unresolved:         1"),
        "human output must state the same unresolved count as json; got:\n{}",
        human.stdout
    );
    assert!(
        human.stdout.contains("doStuff"),
        "human output must name the unresolved method; got:\n{}",
        human.stdout
    );
}

#[test]
fn jni_link_jar_container_links_a_real_committed_jar_against_the_registered_natives_fixture() {
    let jar: PathBuf = corpus_jar();
    assert!(
        jar.exists(),
        "{} is tracked in git and this case grades nothing without it",
        jar.display()
    );
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would \
         leave this case driving nothing",
        cli_binary().display()
    );
    let (_scratch, so_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-jar", "so");
    let native: PathBuf = write_native_lib(so_path.parent().expect("scratch dir"));

    let jar_str: &str = jar.to_str().expect("utf8 jar path");
    let native_str: &str = native.to_str().expect("utf8 native path");
    let json_run: common::Run =
        run_disrobe(&["jvm", "jni", jar_str, "--native", native_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run over a real jar container failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));
    assert_eq!(
        doc["surface"]["code_scan_complete"].as_bool(),
        Some(true),
        "every class in the real corpus jar must parse cleanly; got: {}",
        json_run.stdout
    );
    let registered: &Vec<serde_json::Value> = doc["surface"]["registered_natives"]
        .as_array()
        .expect("surface.registered_natives array");
    assert_eq!(
        registered.len(),
        4,
        "the jar-input path must reach the same native-library linking as the dex-input path; \
         got: {}",
        json_run.stdout
    );
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".bat", ".cmd"]
    } else {
        &[""]
    };
    for dir in std::env::split_paths(&path_var) {
        for ext in exts {
            let candidate: PathBuf = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

#[test]
fn jni_link_statically_resolves_a_real_ndk_and_d8_built_pair() {
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP jni link ndk/d8 leg: javac (JDK) not on PATH");
        return;
    };
    let Some(d8): Option<PathBuf> = find_on_path("d8") else {
        eprintln!("SKIP jni link ndk/d8 leg: d8 (Android build-tools) not on PATH");
        return;
    };
    let Some(clang): Option<PathBuf> = find_on_path("clang") else {
        eprintln!("SKIP jni link ndk/d8 leg: clang (Android NDK) not on PATH");
        return;
    };

    let purpose: String = format!("disrobe_jni_link_ndk_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let classes: PathBuf = dir.join("classes");
    std::fs::create_dir_all(&classes).expect("mkdir classes");

    let src: PathBuf = dir.join("NativeSurface.java");
    std::fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("disrobe-pass-jvm")
            .join("tests")
            .join("fixtures")
            .join("jni")
            .join("NativeSurface.java"),
        &src,
    )
    .expect("copy NativeSurface.java fixture");

    let compiled: Output = Command::new(&javac)
        .arg("-encoding")
        .arg("UTF-8")
        .arg("-d")
        .arg(&classes)
        .arg(&src)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "javac failed: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let dex_out: PathBuf = dir.join("classes.dex");
    let d8_out: Output = Command::new(&d8)
        .arg("--output")
        .arg(&dir)
        .arg(classes.join("com/example/jni/NativeSurface.class"))
        .output()
        .expect("run d8");
    assert!(
        d8_out.status.success(),
        "d8 failed: {}",
        String::from_utf8_lossy(&d8_out.stderr)
    );
    assert!(dex_out.exists(), "d8 must produce classes.dex");

    let c_src: PathBuf = dir.join("stub.c");
    std::fs::write(
        &c_src,
        "typedef int jint;\n\
         typedef void* jobject;\n\
         typedef void* JNIEnv;\n\
         jint Java_com_example_jni_NativeSurface_retInt(JNIEnv *env, jobject thiz) { return 42; }\n",
    )
    .expect("write native stub");
    let so_out: PathBuf = dir.join("libnativesurface.so");
    let cc: Output = Command::new(&clang)
        .arg("-shared")
        .arg("-fPIC")
        .arg("-o")
        .arg(&so_out)
        .arg(&c_src)
        .output()
        .expect("run clang");
    assert!(
        cc.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&cc.stderr)
    );

    let dex_str: &str = dex_out.to_str().expect("utf8 dex path");
    let so_str: &str = so_out.to_str().expect("utf8 so path");
    let json_run: common::Run = run_disrobe(&["jvm", "jni", dex_str, "--native", so_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run over the ndk/d8 pair failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));
    let resolved: u64 = doc["surface"]["resolved_statically"]
        .as_u64()
        .expect("resolved_statically");
    assert!(
        resolved >= 1,
        "the NDK-built add() native must resolve statically against the real .so; got: {}",
        json_run.stdout
    );
    eprintln!(
        "jni_link_statically_resolves_a_real_ndk_and_d8_built_pair: {resolved} native(s) \
         resolved statically against a real NDK clang .so"
    );
}

fn corpus_aar() -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus/jvm/aar/fixture-native-module.aar");
    p
}

#[test]
fn jni_link_aar_resolves_the_nested_classes_jar_native_and_recovers_registered_natives() {
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would \
         leave this case driving nothing",
        cli_binary().display()
    );
    let aar: PathBuf = corpus_aar();
    assert!(
        aar.exists(),
        "{} is tracked in git and this case grades nothing without it",
        aar.display()
    );
    let aar_str: &str = aar.to_str().expect("utf8 aar path");

    let json_run: common::Run = run_disrobe(&["jvm", "jni", aar_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run over a real .aar failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));

    assert_eq!(
        doc["surface"]["native_method_count"].as_u64(),
        Some(1),
        "the classes.jar-nested add(int,int) native method must be counted; got: {}",
        json_run.stdout
    );
    assert_eq!(
        doc["surface"]["resolved_statically"].as_u64(),
        Some(1),
        "add(int,int) must resolve statically against jni/arm64-v8a/libnativesurface.so; got: {}",
        json_run.stdout
    );
    let registered: &Vec<serde_json::Value> = doc["surface"]["registered_natives"]
        .as_array()
        .expect("surface.registered_natives array");
    assert_eq!(
        registered.len(),
        4,
        "the jni/x86_64/libjnireg_x64.so RegisterNatives table must be recovered the same way \
         proven for .apk/.aab; got: {}",
        json_run.stdout
    );
    let abis: Vec<&str> = doc["surface"]["libraries"]
        .as_array()
        .expect("surface.libraries array")
        .iter()
        .filter_map(|l: &serde_json::Value| l["abi"].as_str())
        .collect();
    assert!(
        abis.contains(&"arm64-v8a") && abis.contains(&"x86_64"),
        "both jni/<abi>/ directories must be named, generalizing the lib/<abi>/ ABI logic; \
         got: {abis:?}"
    );

    let human: common::Run = run_disrobe(&["jvm", "jni", aar_str]);
    assert_eq!(human.code, 0, "jvm jni text run failed: {}", human.stderr);
    assert!(
        human.stdout.contains("resolved static:    1"),
        "human output must agree with json on resolved_statically; got:\n{}",
        human.stdout
    );
    assert!(
        human.stdout.contains("registered natives: 4"),
        "human output must agree with json on registered_natives; got:\n{}",
        human.stdout
    );
}

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::{Cursor, Write as _};
    let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(512));
    let mut zip: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
    let opts: zip::write::SimpleFileOptions =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    for (path, data) in entries {
        zip.start_file(*path, opts).expect("start zip entry");
        zip.write_all(data).expect("write zip entry data");
    }
    zip.finish().expect("finish zip").into_inner()
}

fn build_aarch64_elf_export(export: &str) -> Vec<u8> {
    use object::write::{Object, StandardSection, Symbol, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolFlags, SymbolKind, SymbolScope};
    let mut obj: Object<'_> =
        Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let text: object::write::SectionId = obj.section_id(StandardSection::Text);
    let _offset: u64 = obj.append_section_data(text, &[0x1f, 0x20, 0x03, 0xd5], 4);
    obj.add_symbol(Symbol {
        name: export.as_bytes().to_vec(),
        value: 0,
        size: 4,
        kind: SymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(text),
        flags: SymbolFlags::None,
    });
    obj.write().expect("write elf .so")
}

fn build_split_probe_dex() -> Vec<u8> {
    let mut builder: DexBuilder = DexBuilder::new();
    builder.add_class(ClassDef {
        class: "Lcom/disrobe/fixture/SplitProbe;".to_owned(),
        super_class: "Ljava/lang/Object;".to_owned(),
        access_flags: 0x0001,
        static_fields: Vec::new(),
        static_values: Vec::new(),
        direct_methods: Vec::new(),
        virtual_methods: vec![native_method("Lcom/disrobe/fixture/SplitProbe;", "compute")],
    });
    builder.build()
}

const SPLIT_PROBE_SYMBOL: &str = "Java_com_disrobe_fixture_SplitProbe_compute";

#[test]
fn jni_link_apks_resolves_a_base_dex_native_against_a_config_split_only_symbol() {
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would \
         leave this case driving nothing",
        cli_binary().display()
    );
    let base_apk: Vec<u8> = build_zip(&[("classes.dex", &build_split_probe_dex())]);
    let split_so: Vec<u8> = build_aarch64_elf_export(SPLIT_PROBE_SYMBOL);
    let split_apk: Vec<u8> = build_zip(&[("lib/arm64-v8a/libsplitnative.so", &split_so)]);
    let apks: Vec<u8> = build_zip(&[
        ("base-master.apk", &base_apk),
        ("split_config.arm64_v8a.apk", &split_apk),
    ]);

    let (_scratch, apks_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-apks", "apks");
    std::fs::write(&apks_path, &apks).expect("write apks fixture");
    let apks_str: &str = apks_path.to_str().expect("utf8 apks path");

    let json_run: common::Run = run_disrobe(&["jvm", "jni", apks_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run over a synthetic .apks split set failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));
    assert_eq!(
        doc["surface"]["native_method_count"].as_u64(),
        Some(1),
        "the base split's declared compute() native must be counted; got: {}",
        json_run.stdout
    );
    assert_eq!(
        doc["surface"]["resolved_statically"].as_u64(),
        Some(1),
        "compute() must resolve against a symbol that exists only in the config split's .so; \
         got: {}",
        json_run.stdout
    );
}

#[test]
fn jni_link_base_apk_plus_native_split_apk_resolves_across_the_split_boundary() {
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would \
         leave this case driving nothing",
        cli_binary().display()
    );
    let base_apk: Vec<u8> = build_zip(&[("classes.dex", &build_split_probe_dex())]);
    let split_so: Vec<u8> = build_aarch64_elf_export(SPLIT_PROBE_SYMBOL);
    let split_apk: Vec<u8> = build_zip(&[("lib/arm64-v8a/libsplitnative.so", &split_so)]);

    let (_base_scratch, base_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-base-apk", "apk");
    std::fs::write(&base_path, &base_apk).expect("write base apk fixture");
    let (_split_scratch, split_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-split-apk", "apk");
    std::fs::write(&split_path, &split_apk).expect("write split apk fixture");

    let base_str: &str = base_path.to_str().expect("utf8 base apk path");
    let split_str: &str = split_path.to_str().expect("utf8 split apk path");
    let json_run: common::Run =
        run_disrobe(&["jvm", "jni", base_str, "--native", split_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run over a base apk plus a --native split apk failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));
    assert_eq!(
        doc["surface"]["native_method_count"].as_u64(),
        Some(1),
        "the base apk's declared compute() native must be counted; got: {}",
        json_run.stdout
    );
    assert_eq!(
        doc["surface"]["resolved_statically"].as_u64(),
        Some(1),
        "compute() must resolve against the --native split apk's own .so; got: {}",
        json_run.stdout
    );
}

fn build_oat_dex_wrapper(dex_bytes: &[u8]) -> Vec<u8> {
    use object::write::{Object, StandardSection, Symbol, SymbolFlags, SymbolSection};
    use object::{Architecture, BinaryFormat, Endianness, SymbolKind, SymbolScope};

    const OAT_HEADER_FIXED_SIZE: u32 = 56;
    let location: &str = "base.apk!classes.dex";
    let mut entry: Vec<u8> = Vec::new();
    entry.extend_from_slice(&(location.len() as u32).to_le_bytes());
    entry.extend_from_slice(location.as_bytes());
    entry.extend_from_slice(&0x0BAD_F00Du32.to_le_bytes());
    let dex_file_offset: u32 = OAT_HEADER_FIXED_SIZE + entry.len() as u32 + 4;
    entry.extend_from_slice(&dex_file_offset.to_le_bytes());

    let mut rodata: Vec<u8> = Vec::new();
    rodata.extend_from_slice(b"oat\n");
    rodata.extend_from_slice(b"170\0");
    rodata.extend_from_slice(&0u32.to_le_bytes());
    rodata.extend_from_slice(&2i32.to_le_bytes());
    rodata.extend_from_slice(&0u32.to_le_bytes());
    rodata.extend_from_slice(&1u32.to_le_bytes());
    rodata.extend_from_slice(&OAT_HEADER_FIXED_SIZE.to_le_bytes());
    for _ in 0..6 {
        rodata.extend_from_slice(&0u32.to_le_bytes());
    }
    rodata.extend_from_slice(&0u32.to_le_bytes());
    rodata.extend_from_slice(&entry);
    rodata.extend_from_slice(dex_bytes);

    let mut obj: Object<'_> =
        Object::new(BinaryFormat::Elf, Architecture::Aarch64, Endianness::Little);
    let sec: object::write::SectionId = obj.section_id(StandardSection::ReadOnlyData);
    let off: u64 = obj.append_section_data(sec, &rodata, 16);
    obj.add_symbol(Symbol {
        name: b"oatdata".to_vec(),
        value: off,
        size: rodata.len() as u64,
        kind: SymbolKind::Data,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(sec),
        flags: SymbolFlags::None,
    });
    obj.write().expect("write elf oat wrapper")
}

#[test]
fn jni_link_oat_input_wiring_reaches_extract_oat_dex_on_a_header_shaped_fixture() {
    assert!(
        cli_binary().exists(),
        "cargo builds the disrobe binary before this test binary runs, so a missing {} would \
         leave this case driving nothing",
        cli_binary().display()
    );
    let dex: Vec<u8> = build_split_probe_dex();
    let oat_bytes: Vec<u8> = build_oat_dex_wrapper(&dex);
    let (_oat_scratch, oat_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-oat", "oat");
    std::fs::write(&oat_path, &oat_bytes).expect("write oat fixture");
    let so: Vec<u8> = build_aarch64_elf_export(SPLIT_PROBE_SYMBOL);
    let (_so_scratch, so_path): (disrobe_core::scratch::ScratchDir, PathBuf) =
        temp_path("jni-link-oat-so", "so");
    std::fs::write(&so_path, &so).expect("write so fixture");

    let oat_str: &str = oat_path.to_str().expect("utf8 oat path");
    let so_str: &str = so_path.to_str().expect("utf8 so path");
    let json_run: common::Run = run_disrobe(&["jvm", "jni", oat_str, "--native", so_str, "--json"]);
    assert_eq!(
        json_run.code, 0,
        "jvm jni json run over a header-shaped .oat fixture failed: {}",
        json_run.stderr
    );
    let doc: serde_json::Value = serde_json::from_str(&json_run.stdout)
        .unwrap_or_else(|e| panic!("jvm jni --json is not valid json: {e}\n{}", json_run.stdout));
    assert_eq!(
        doc["surface"]["native_method_count"].as_u64(),
        Some(1),
        "the embedded dex's declared compute() native must be counted, proving the CLI reaches \
         extract_oat_dex for a raw .oat input; got: {}",
        json_run.stdout
    );
    assert_eq!(
        doc["surface"]["resolved_statically"].as_u64(),
        Some(1),
        "compute() must resolve against the --native .so; got: {}",
        json_run.stdout
    );
}
