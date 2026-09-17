#![allow(clippy::expect_used)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[cfg(feature = "chain")]
use disrobe_core::chain::Pass;
use disrobe_core::scratch::ScratchDir;
#[cfg(feature = "chain")]
use disrobe_core::{Artifact, Rung};
#[cfg(feature = "chain")]
use disrobe_pass_jvm::chain_detector::JVM_PASS;
use disrobe_pass_jvm::dalvik::{DalvikInsn, decode_method};
use disrobe_pass_jvm::{
    DecompiledDex, DexCodeState, DexFile, MethodId, decompile_dex, parse_code_items, parse_dex,
};

const EDGECASES_DEX: &[u8] = include_bytes!("../../../corpus/jvm/dex/EdgeCases.dex");
const EDGECASES_JAVA: &str = include_str!("../../../corpus/jvm/megafile/EdgeCases.java");

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path: OsString = std::env::var_os("PATH")?;
    let extensions: &[&str] = if cfg!(windows) {
        &[".exe", ".cmd", ".bat", ""]
    } else {
        &[""]
    };
    std::env::split_paths(&path).find_map(|directory: PathBuf| {
        extensions.iter().find_map(|extension: &&str| {
            let candidate: PathBuf = directory.join(format!("{name}{extension}"));
            candidate.is_file().then_some(candidate)
        })
    })
}

fn method_source<'a>(source: &'a str, signature: &str) -> Option<&'a str> {
    let start: usize = source.find(signature)?;
    let body_start: usize = source[start..]
        .find('{')
        .map(|offset: usize| start + offset)?;
    let mut depth: usize = 0;
    for (offset, ch) in source[body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return source.get(start..=body_start + offset);
                }
            }
            _ => {}
        }
    }
    None
}

fn execute_static_repository(
    javac: &Path,
    java: &Path,
    interface_method: &str,
    implementation: &str,
    label: &str,
) -> Output {
    let scratch: ScratchDir = ScratchDir::create(label).expect("create scratch");
    let package: PathBuf = scratch.path().join("EdgeCases");
    std::fs::create_dir_all(&package).expect("create Java package directory");
    let repository: String = format!(
        "package EdgeCases; public interface Repository {{ Object get(Object key); void put(Object key, Object value); {interface_method} }}"
    );
    let repository_path: PathBuf = package.join("Repository.java");
    let implementation_path: PathBuf = package.join("Repository$_1.java");
    let probe_path: PathBuf = package.join("RepositoryProbe.java");
    std::fs::write(&repository_path, repository).expect("write recovered interface slice");
    std::fs::write(&implementation_path, implementation).expect("write recovered implementation");
    let probe: &str = "package EdgeCases; final class RepositoryProbe { public static void main(String[] args) { Repository repository = Repository.inMemory(); if (repository == null) throw new AssertionError(); repository.put(\"key\", Integer.valueOf(7)); System.out.print(repository.get(\"key\")); } }";
    std::fs::write(&probe_path, probe).expect("write Java behavior probe");
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&repository_path)
        .arg(&implementation_path)
        .arg(&probe_path)
        .output()
        .expect("compile recovered static-interface slice");
    assert!(
        compiled.status.success(),
        "recovered static-interface slice did not compile:\n{}\n{}\n{}",
        String::from_utf8_lossy(&compiled.stderr),
        std::fs::read_to_string(&repository_path).expect("read interface diagnostic"),
        implementation
    );
    Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("EdgeCases.RepositoryProbe")
        .output()
        .expect("run Java behavior probe")
}

fn execute_authored_repository(javac: &Path, java: &Path) -> Output {
    let scratch: ScratchDir =
        ScratchDir::create("d8-static-interface-authored").expect("create authored scratch");
    let source_path: PathBuf = scratch.path().join("EdgeCases.java");
    let probe_path: PathBuf = scratch.path().join("AuthoredRepositoryProbe.java");
    std::fs::write(&source_path, EDGECASES_JAVA).expect("write paired authored source");
    let probe: &str = "final class AuthoredRepositoryProbe { public static void main(String[] args) { EdgeCases.Repository<String, Integer> repository = EdgeCases.Repository.inMemory(); repository.put(\"key\", Integer.valueOf(7)); System.out.print(repository.get(\"key\")); } }";
    std::fs::write(&probe_path, probe).expect("write authored behavior probe");
    let compiled: Output = Command::new(javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .arg(&probe_path)
        .output()
        .expect("compile paired authored source");
    assert!(
        compiled.status.success(),
        "paired authored source did not compile:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("AuthoredRepositoryProbe")
        .output()
        .expect("run authored behavior probe")
}

fn assert_companion_preserved(dex: &DexFile, bytes: &[u8], label: &str) {
    let recovered: DecompiledDex = decompile_dex(dex, bytes);
    let repository: &String = recovered
        .sources
        .get("EdgeCases/Repository.java")
        .expect("recover Repository");
    assert!(
        repository.contains("public abstract class Repository"),
        "{label}: {repository}"
    );
    assert!(
        !repository.contains("public static EdgeCases.Repository inMemory("),
        "{label}: {repository}"
    );
    assert!(
        recovered
            .sources
            .contains_key("EdgeCases/Repository$_u002D_CC.java")
    );
}

#[test]
fn real_d8_default_interface_companion_returns_to_source_shape() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let shape: &String = recovered
        .sources
        .get("EdgeCases/Shape.java")
        .expect("recover Shape");

    assert!(shape.contains("public interface Shape"), "{shape}");
    assert!(shape.contains("default String label()"), "{shape}");
    assert!(shape.contains("new StringBuilder(\"shape:\")"), "{shape}");
    assert!(shape.contains("this.getClass()"), "{shape}");
    assert!(!shape.contains("abstract String label()"), "{shape}");
    assert!(
        !recovered
            .sources
            .contains_key("EdgeCases/Shape$_u002D_CC.java")
    );

    for implementation in ["Circle", "Square", "Triangle", "EmptyShape"] {
        let path: String = format!("EdgeCases/{implementation}.java");
        let source: &String = recovered
            .sources
            .get(&path)
            .expect("recover implementation");
        assert!(
            source.contains("implements EdgeCases.Shape"),
            "{path}: {source}"
        );
        assert!(!source.contains("$default$label"), "{path}: {source}");
        assert!(!source.contains(" String label()"), "{path}: {source}");
    }

    assert!(
        !recovered
            .sources
            .contains_key("EdgeCases/Repository$_u002D_CC.java"),
        "a fully recovered default/static companion must be elided"
    );

    let javac: PathBuf = find_on_path("javac")
        .expect("the D8 default-interface recovery gate requires javac on PATH");
    let scratch: ScratchDir = ScratchDir::create("d8-default-interface").expect("create scratch");
    let package: PathBuf = scratch.path().join("EdgeCases");
    std::fs::create_dir_all(&package).expect("create Java package directory");
    let source_path: PathBuf = package.join("Shape.java");
    std::fs::write(&source_path, shape).expect("write recovered interface");
    let compiled: Output = Command::new(&javac)
        .arg("-d")
        .arg(scratch.path())
        .arg(&source_path)
        .output()
        .expect("run javac");
    assert!(
        compiled.status.success(),
        "recovered D8 interface did not compile under javac:\n{}\n{shape}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    let probe_path: PathBuf = package.join("Probe.java");
    let probe: &str = "package EdgeCases; final class Probe implements Shape { public double area() { return 0.0; } public static void main(String[] args) { if (!new Probe().label().equals(\"shape:probe\")) throw new AssertionError(); } }";
    std::fs::write(&probe_path, probe).expect("write Java behavior probe");
    let compiled_probe: Output = Command::new(&javac)
        .arg("-cp")
        .arg(scratch.path())
        .arg("-d")
        .arg(scratch.path())
        .arg(&probe_path)
        .output()
        .expect("compile Java behavior probe");
    assert!(
        compiled_probe.status.success(),
        "behavior probe did not compile:\n{}",
        String::from_utf8_lossy(&compiled_probe.stderr)
    );
    let java: PathBuf =
        find_on_path("java").expect("the D8 default-interface recovery gate requires java on PATH");
    let executed: Output = Command::new(java)
        .arg("-cp")
        .arg(scratch.path())
        .arg("EdgeCases.Probe")
        .output()
        .expect("run Java behavior probe");
    assert!(
        executed.status.success(),
        "recovered default method changed behavior:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn real_d8_static_interface_methods_return_to_source_shape() {
    let dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse real D8 artifact");
    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let repository: &String = recovered
        .sources
        .get("EdgeCases/Repository.java")
        .expect("recover Repository");

    assert!(
        repository.contains("default boolean containsKey("),
        "{repository}"
    );
    assert!(
        repository.contains("default java.util.Optional find("),
        "{repository}"
    );
    assert!(
        repository.contains("public static EdgeCases.Repository inMemory("),
        "{repository}"
    );
    assert!(
        repository.contains("public static String formatKey("),
        "{repository}"
    );
    assert!(
        !recovered
            .sources
            .contains_key("EdgeCases/Repository$_u002D_CC.java"),
        "a fully recovered static/default companion must be elided"
    );
    assert!(
        recovered
            .sources
            .values()
            .all(|source: &String| !source.contains("Repository$_u002D_CC")),
        "every exact invoke-static call must target the authored interface"
    );
    #[cfg(feature = "chain")]
    {
        let input: Artifact = Artifact::new(Rung::Raw, EDGECASES_DEX.to_vec(), [0u8; 32]);
        let surfaced: Artifact = JVM_PASS
            .run(&input)
            .expect("registered JVM pass decompiles DEX");
        let surfaced_source: &str =
            std::str::from_utf8(&surfaced.envelope).expect("registered pass emits UTF-8 source");
        assert!(
            surfaced_source.contains("public static EdgeCases.Repository inMemory("),
            "{surfaced_source}"
        );
        assert!(!surfaced_source.contains("Repository$_u002D_CC"));
    }

    let recovered_implementation: &String = recovered
        .sources
        .get("EdgeCases/Repository$_1.java")
        .expect("recover Repository implementation");
    assert!(
        recovered_implementation.contains("implements EdgeCases.Repository"),
        "{recovered_implementation}"
    );
    let implementation: &str = "package EdgeCases; public final class Repository$_1 implements Repository { private final java.util.Map<Object, Object> store = new java.util.concurrent.ConcurrentHashMap<>(); public Object get(Object key) { return store.get(key); } public void put(Object key, Object value) { store.put(key, value); } }";
    let recovered_method: &str =
        method_source(repository, "public static EdgeCases.Repository inMemory(")
            .expect("extract recovered inMemory method");
    let javac: PathBuf = find_on_path("javac")
        .expect("the D8 static-interface recovery gate requires javac on PATH");
    let java: PathBuf =
        find_on_path("java").expect("the D8 static-interface recovery gate requires java on PATH");
    let executed: Output = execute_static_repository(
        &javac,
        &java,
        recovered_method,
        implementation,
        "d8-static-interface",
    );
    assert!(
        executed.status.success(),
        "recovered static/default interface behavior changed:\n{}",
        String::from_utf8_lossy(&executed.stderr)
    );
    let authored: Output = execute_authored_repository(&javac, &java);
    assert!(
        authored.status.success(),
        "paired authored interface behavior failed:\n{}",
        String::from_utf8_lossy(&authored.stderr)
    );
    assert_eq!(executed.stdout, authored.stdout);
    let mutated_method: String =
        recovered_method.replacen("return new EdgeCases.Repository$_1();", "return null;", 1);
    assert_ne!(mutated_method, recovered_method);
    let mutated: Output = execute_static_repository(
        &javac,
        &java,
        &mutated_method,
        implementation,
        "d8-static-interface-mutated",
    );
    assert!(!mutated.status.success());
}

#[test]
fn ambiguous_static_companion_method_preserves_the_complete_companion() {
    let mut dex: DexFile = parse_dex(EDGECASES_DEX).expect("parse mutation source");
    let method: &mut MethodId = dex
        .method_ids
        .iter_mut()
        .find(|method: &&mut MethodId| {
            method.class.ends_with("Repository$-CC;") && method.name == "formatKey"
        })
        .expect("find static companion method");
    method.name = "<clinit>".to_string();

    let recovered: DecompiledDex = decompile_dex(&dex, EDGECASES_DEX);
    let repository: &String = recovered
        .sources
        .get("EdgeCases/Repository.java")
        .expect("recover Repository");
    assert!(repository.contains("public abstract class Repository"));
    assert!(!repository.contains("public static EdgeCases.Repository inMemory("));
    assert!(
        recovered
            .sources
            .contains_key("EdgeCases/Repository$_u002D_CC.java")
    );
}

#[test]
fn malformed_static_companion_call_arity_preserves_the_complete_companion() {
    let mut missing_word: DexFile = parse_dex(EDGECASES_DEX).expect("parse missing-word mutation");
    let in_memory: &mut MethodId = missing_word
        .method_ids
        .iter_mut()
        .find(|method: &&mut MethodId| {
            method.class.ends_with("Repository$-CC;") && method.name == "inMemory"
        })
        .expect("find zero-arity static companion method");
    assert!(in_memory.proto.parameters.is_empty());
    in_memory.proto.parameters.push("J".to_string());
    assert_companion_preserved(&missing_word, EDGECASES_DEX, "missing");

    let original: DexFile = parse_dex(EDGECASES_DEX).expect("parse surplus-word source");
    let in_memory_index: u32 = u32::try_from(
        original
            .method_ids
            .iter()
            .position(|method: &MethodId| {
                method.class.ends_with("Repository$-CC;") && method.name == "inMemory"
            })
            .expect("find invoked static companion method"),
    )
    .expect("method index fits u32");
    let report = parse_code_items(&original, EDGECASES_DEX);
    let mut call_location: Option<(u32, u32)> = None;
    for metadata in report.methods() {
        let DexCodeState::Decoded(item_index) = metadata.state else {
            continue;
        };
        let Some(item) = report.decoded().get(item_index) else {
            continue;
        };
        if let Some(call) = decode_method(&item.insns)
            .iter()
            .find(|insn: &&DalvikInsn| {
                matches!(insn.op, 0x71 | 0x77) && insn.index == Some(in_memory_index)
            })
        {
            call_location = Some((metadata.code_offset, call.pc));
            break;
        }
    }
    let (code_offset, call_pc): (u32, u32) = call_location.expect("find inMemory invoke-static");
    let instruction_offset: usize = usize::try_from(code_offset)
        .expect("code offset fits usize")
        .checked_add(16)
        .and_then(|offset: usize| {
            usize::try_from(call_pc)
                .ok()
                .and_then(|pc: usize| pc.checked_mul(2))
                .and_then(|pc: usize| offset.checked_add(pc))
        })
        .expect("instruction offset is representable");
    let mut surplus_bytes: Vec<u8> = EDGECASES_DEX.to_vec();
    let word: &mut [u8] = surplus_bytes
        .get_mut(instruction_offset..instruction_offset + 2)
        .expect("invoke word is in bounds");
    let original_word: u16 = u16::from_le_bytes([word[0], word[1]]);
    assert_eq!(original_word >> 12, 0);
    word.copy_from_slice(&(original_word | 0x1000).to_le_bytes());
    let surplus_word: DexFile = parse_dex(&surplus_bytes).expect("parse surplus-word mutation");
    assert_companion_preserved(&surplus_word, &surplus_bytes, "surplus");
}
