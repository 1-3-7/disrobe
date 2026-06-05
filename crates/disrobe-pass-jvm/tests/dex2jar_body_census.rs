#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::PathBuf;

use disrobe_pass_jvm::bytecode::{CodeAttribute, Instruction, disassemble, parse_code_attribute};
use disrobe_pass_jvm::classfile::{Attribute, ClassFile, MethodInfo};
use disrobe_pass_jvm::dex2jar::{Dex2JarResult, translate_dex_bytes};
use disrobe_pass_jvm::parse_classfile;

fn corpus(parts: &[&str]) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    for part in parts {
        p.push(part);
    }
    p
}

fn baseline_classes() -> BTreeMap<String, Vec<u8>> {
    let bytes: Vec<u8> =
        std::fs::read(corpus(&["jvm", "megafile", "EdgeCases-baseline.jar"])).expect("read jar");
    let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(bytes);
    let mut zip: zip::ZipArchive<std::io::Cursor<Vec<u8>>> =
        zip::ZipArchive::new(cursor).expect("open jar");
    let mut out: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..zip.len() {
        let mut f: zip::read::ZipFile<'_> = zip.by_index(i).expect("entry");
        let name: String = f.name().to_string();
        if name.ends_with(".class") {
            let mut buf: Vec<u8> = Vec::new();
            f.read_to_end(&mut buf).expect("read class");
            out.insert(name[..name.len() - 6].to_string(), buf);
        }
    }
    out
}

fn translated_classes() -> BTreeMap<String, Vec<u8>> {
    let dex_bytes: Vec<u8> = std::fs::read(corpus(&["jvm", "dex", "EdgeCases.dex"])).expect("dex");
    let result: Dex2JarResult = translate_dex_bytes(&dex_bytes).expect("translate");
    result
        .jar_entries
        .into_iter()
        .filter(|(name, _)| name.ends_with(".class"))
        .map(|(name, bytes)| (name[..name.len() - 6].to_string(), bytes))
        .collect()
}

fn find_code(cf: &ClassFile, method: &MethodInfo) -> Option<CodeAttribute> {
    for attr in &method.attributes {
        let attr: &Attribute = attr;
        if cf.utf8_at(attr.name_index).ok()? == "Code" {
            return parse_code_attribute(&attr.info).ok();
        }
    }
    None
}

fn is_register_shuffle(mnemonic: &str) -> bool {
    mnemonic.ends_with("load")
        || mnemonic.contains("load_")
        || mnemonic.ends_with("store")
        || mnemonic.contains("store_")
        || matches!(
            mnemonic,
            "nop"
                | "dup"
                | "dup_x1"
                | "dup_x2"
                | "dup2"
                | "dup2_x1"
                | "dup2_x2"
                | "swap"
                | "pop"
                | "pop2"
        )
}

fn semantic_skeleton(code: &CodeAttribute) -> Vec<&'static str> {
    let insns: Vec<Instruction> = disassemble(&code.code).expect("disassemble code");
    insns
        .into_iter()
        .map(|i: Instruction| i.mnemonic)
        .filter(|m: &&'static str| !is_register_shuffle(m))
        .collect()
}

fn is_const(mnemonic: &str) -> bool {
    mnemonic.starts_with("iconst")
        || mnemonic.starts_with("lconst")
        || mnemonic.starts_with("fconst")
        || mnemonic.starts_with("dconst")
        || mnemonic.starts_with("aconst")
        || matches!(mnemonic, "bipush" | "sipush" | "ldc" | "ldc_w" | "ldc2_w")
}

fn normalize(skel: Vec<&'static str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(skel.len());
    for m in skel {
        let token: String = if is_const(m) {
            "const".to_string()
        } else {
            m.to_string()
        };
        if out.last() != Some(&token) {
            out.push(token);
        }
    }
    out
}

/// A recovered body is a stub when it is the canonical
/// `new UnsupportedOperationException; dup; invokespecial; athrow` sequence.
fn is_stub(code: &CodeAttribute) -> bool {
    let insns: Vec<Instruction> = disassemble(&code.code).expect("disassemble");
    insns.len() <= 4 && insns.iter().any(|i: &Instruction| i.mnemonic == "athrow")
}

fn method_table(cf: &ClassFile) -> BTreeMap<(String, String), CodeAttribute> {
    let mut out: BTreeMap<(String, String), CodeAttribute> = BTreeMap::new();
    for m in &cf.methods {
        let name: String = match cf.utf8_at(m.name_index) {
            Ok(n) => n.to_string(),
            Err(_) => continue,
        };
        let desc: String = match cf.utf8_at(m.descriptor_index) {
            Ok(d) => d.to_string(),
            Err(_) => continue,
        };
        if let Some(code) = find_code(cf, m) {
            out.insert((name, desc), code);
        }
    }
    out
}

/// Non-circular per-method body fidelity across the whole corpus, measured against the `javac` baseline.
#[test]
fn report_whole_corpus_body_fidelity() {
    let translated: BTreeMap<String, Vec<u8>> = translated_classes();
    let baseline: BTreeMap<String, Vec<u8>> = baseline_classes();

    let mut comparable: usize = 0;
    let mut recovered_real: usize = 0;
    let mut matched: usize = 0;
    let mut mismatch_samples: Vec<String> = Vec::new();

    for (class, bbytes) in &baseline {
        let Some(tbytes): Option<&Vec<u8>> = translated.get(class) else {
            continue;
        };
        let (tcf, bcf): (ClassFile, ClassFile) = (
            parse_classfile(tbytes).expect("parse translated"),
            parse_classfile(bbytes).expect("parse baseline"),
        );
        let ttab: BTreeMap<(String, String), CodeAttribute> = method_table(&tcf);
        let btab: BTreeMap<(String, String), CodeAttribute> = method_table(&bcf);
        for (key, bcode) in &btab {
            let Some(tcode): Option<&CodeAttribute> = ttab.get(key) else {
                continue;
            };
            comparable += 1;
            if is_stub(tcode) {
                continue;
            }
            recovered_real += 1;
            let ok: bool =
                normalize(semantic_skeleton(tcode)) == normalize(semantic_skeleton(bcode));
            if ok {
                matched += 1;
            } else if mismatch_samples.len() < 12 {
                mismatch_samples.push(format!(
                    "MISMATCH {class}.{}{}: t={:?} b={:?}",
                    key.0,
                    key.1,
                    semantic_skeleton(tcode),
                    semantic_skeleton(bcode)
                ));
            }
        }
    }

    let rec_pct: f64 = recovered_real as f64 * 100.0 / comparable.max(1) as f64;
    let match_of_rec: f64 = matched as f64 * 100.0 / recovered_real.max(1) as f64;
    let match_of_all: f64 = matched as f64 * 100.0 / comparable.max(1) as f64;
    eprintln!(
        "CORPUS BODY FIDELITY: comparable_methods={comparable} recovered_real_body={recovered_real} ({rec_pct:.1}% of comparable) skeleton_matched={matched} ({match_of_rec:.1}% of recovered, {match_of_all:.1}% of comparable)"
    );
    for s in &mismatch_samples {
        eprintln!("  {s}");
    }
}
