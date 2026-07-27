#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_pass_jvm::bytecode::{CodeAttribute, Instruction, disassemble};
use disrobe_pass_jvm::decompile_struct::{Cfg, build_cfg};
use disrobe_pass_jvm::{
    FrameInferOutcome, FrameInferReport, FrameState, JavaType, MethodDescriptor, VerificationType,
    infer_frames,
};

const L_OFFSET_EXPECTED: u16 = 25;

fn conv_code() -> (Vec<u8>, u16) {
    let mut code: Vec<u8> = Vec::new();
    code.extend([0x22, 0x8C, 0x37, 0x04]);
    code.extend([0x22, 0x8D, 0x39, 0x06]);
    code.extend([0x27, 0x8E, 0x36, 0x08]);
    code.extend([0x27, 0x8F, 0x37, 0x09]);
    code.extend([0x27, 0x90, 0x38, 0x0B]);
    code.push(0x1D);
    let ifeq_off: usize = code.len();
    code.extend([0x99, 0x00, 0x00]);
    code.push(0x00);
    let l_off: usize = code.len();
    let delta: i16 = i16::try_from(l_off - ifeq_off).expect("branch delta fits i16");
    code[ifeq_off + 1..ifeq_off + 3].copy_from_slice(&delta.to_be_bytes());
    code.extend([0x16, 0x04, 0x88]);
    code.extend([0x18, 0x06, 0x8E, 0x60]);
    code.extend([0x15, 0x08, 0x60]);
    code.extend([0x16, 0x09, 0x88, 0x60]);
    code.extend([0x17, 0x0B, 0x8B, 0x60]);
    code.push(0xAC);
    (code, u16::try_from(l_off).expect("l_off fits u16"))
}

fn conv_descriptor() -> MethodDescriptor {
    MethodDescriptor {
        params: vec![JavaType::Float, JavaType::Double, JavaType::Int],
        returns: JavaType::Int,
    }
}

fn inferred_join_frame() -> (FrameState, u16) {
    let (code, l_off): (Vec<u8>, u16) = conv_code();
    let insns: Vec<Instruction> = disassemble(&code).expect("disassemble conv");
    let attr: CodeAttribute = CodeAttribute {
        max_stack: 4,
        max_locals: 12,
        code,
        exception_table: Vec::new(),
        dropped_exception_entries: 0,
        nested_attribute_name_indices: Vec::new(),
    };
    let cfg: Cfg = build_cfg(&insns, &attr, |_| None).expect("build cfg");
    let desc: MethodDescriptor = conv_descriptor();
    let report: FrameInferReport = infer_frames(
        &cfg,
        &insns,
        &desc,
        true,
        false,
        "Conv",
        &|_| None,
        &|_| None,
        &|_| None,
        &|_| None,
    );
    assert_eq!(
        report.outcome,
        FrameInferOutcome::Converged,
        "frame inference over the numeric-conversion method must reach a fixed point"
    );
    let frame: FrameState = report
        .block_entry_frames
        .get(&u32::from(l_off))
        .cloned()
        .expect("a join frame is inferred at the branch target that follows the conversions");
    (frame, l_off)
}

fn vt_tag(vt: &VerificationType) -> u8 {
    match vt {
        VerificationType::Top => 0,
        VerificationType::Integer => 1,
        VerificationType::Float => 2,
        VerificationType::Double => 3,
        VerificationType::Long => 4,
        VerificationType::Null => 5,
        VerificationType::UninitializedThis => 6,
        VerificationType::Object(_) => {
            panic!("the conversion method has no object locals; object frame entries unexpected")
        }
    }
}

fn collapse_locals(frame: &FrameState) -> Vec<u8> {
    let mut tags: Vec<u8> = Vec::new();
    let mut i: usize = 0;
    while i < frame.locals.len() {
        let vt: &VerificationType = &frame.locals[i];
        tags.push(vt_tag(vt));
        i += if matches!(vt, VerificationType::Long | VerificationType::Double) {
            2
        } else {
            1
        };
    }
    tags
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn push_utf8(out: &mut Vec<u8>, s: &str) {
    out.push(1);
    push_u16(out, u16::try_from(s.len()).expect("utf8 fits"));
    out.extend_from_slice(s.as_bytes());
}

fn build_conv_class(local_tags: &[u8], l_off: u16) -> (Vec<u8>, Vec<usize>) {
    let (code, _l): (Vec<u8>, u16) = conv_code();

    let mut smt_body: Vec<u8> = Vec::new();
    push_u16(&mut smt_body, 1);
    smt_body.push(255);
    push_u16(&mut smt_body, l_off);
    push_u16(
        &mut smt_body,
        u16::try_from(local_tags.len()).expect("locals fit"),
    );
    let smt_locals_start: usize = smt_body.len();
    for &tag in local_tags {
        smt_body.push(tag);
    }
    push_u16(&mut smt_body, 0);

    let mut code_attr: Vec<u8> = Vec::new();
    push_u16(&mut code_attr, 4);
    push_u16(&mut code_attr, 12);
    push_u32(
        &mut code_attr,
        u32::try_from(code.len()).expect("code len fits"),
    );
    code_attr.extend_from_slice(&code);
    push_u16(&mut code_attr, 0);
    push_u16(&mut code_attr, 1);
    let smt_attr_off_in_code: usize = code_attr.len();
    push_u16(&mut code_attr, 8);
    push_u32(
        &mut code_attr,
        u32::try_from(smt_body.len()).expect("smt len fits"),
    );
    let smt_body_off_in_code: usize = code_attr.len();
    code_attr.extend_from_slice(&smt_body);
    let _ = smt_attr_off_in_code;

    let mut class: Vec<u8> = Vec::new();
    push_u32(&mut class, 0xCAFE_BABE);
    push_u16(&mut class, 0);
    push_u16(&mut class, 52);
    push_u16(&mut class, 9);
    push_utf8(&mut class, "Conv");
    class.push(7);
    push_u16(&mut class, 1);
    push_utf8(&mut class, "java/lang/Object");
    class.push(7);
    push_u16(&mut class, 3);
    push_utf8(&mut class, "conv");
    push_utf8(&mut class, "(FDI)I");
    push_utf8(&mut class, "Code");
    push_utf8(&mut class, "StackMapTable");
    push_u16(&mut class, 0x0021);
    push_u16(&mut class, 2);
    push_u16(&mut class, 4);
    push_u16(&mut class, 0);
    push_u16(&mut class, 0);
    push_u16(&mut class, 1);
    push_u16(&mut class, 0x0009);
    push_u16(&mut class, 5);
    push_u16(&mut class, 6);
    push_u16(&mut class, 1);
    push_u16(&mut class, 7);
    push_u32(
        &mut class,
        u32::try_from(code_attr.len()).expect("code attr len fits"),
    );
    let code_attr_off_in_class: usize = class.len();
    class.extend_from_slice(&code_attr);
    push_u16(&mut class, 0);

    let smt_locals_abs: usize = code_attr_off_in_class + smt_body_off_in_code + smt_locals_start;
    let tag_offsets: Vec<usize> = (0..local_tags.len()).map(|i| smt_locals_abs + i).collect();
    (class, tag_offsets)
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path_var: std::ffi::OsString = std::env::var_os("PATH")?;
    let exts: &[&str] = if cfg!(windows) { &["", ".exe"] } else { &[""] };
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

const PROBE_SRC: &str = r#"
public class Probe {
    public static void main(String[] a) throws Throwable {
        Class<?> c = Class.forName("Conv", true, Probe.class.getClassLoader());
        c.getDeclaredMethods();
        java.lang.reflect.Method m = c.getMethod("conv", float.class, double.class, int.class);
        Object r = m.invoke(null, 3.0f, 5.0, 1);
        System.out.println("verify_ok=1 " + r);
    }
}
"#;

fn verify_dir(java: &PathBuf, dir: &std::path::Path) -> std::process::Output {
    Command::new(java)
        .arg("-Xverify:all")
        .arg("-cp")
        .arg(dir)
        .arg("Probe")
        .output()
        .expect("run java probe")
}

#[test]
fn inferred_conversion_frame_has_the_result_types_and_widths() {
    let (frame, l_off): (FrameState, u16) = inferred_join_frame();
    assert_eq!(l_off, L_OFFSET_EXPECTED, "branch target offset is stable");
    let tags: Vec<u8> = collapse_locals(&frame);
    eprintln!("inferred join-frame local tags at pc {l_off}: {tags:?}");
    assert_eq!(
        tags,
        vec![2, 3, 1, 4, 3, 1, 4, 2],
        "the join frame must record float f, double d, int cond, then the conversion results: \
         f2l -> Long, f2d -> Double, d2i -> Integer, d2l -> Long, d2f -> Float (tags \
         Top=0/Integer=1/Float=2/Double=3/Long=4)"
    );
}

#[test]
fn inferred_conversion_frame_passes_the_real_jvm_verifier() {
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        eprintln!("SKIP conversion-frame verifier gate: java not on PATH (CORPUS-BLOCKED)");
        return;
    };
    let Some(javac): Option<PathBuf> = find_on_path("javac") else {
        eprintln!("SKIP conversion-frame verifier gate: javac not on PATH (CORPUS-BLOCKED)");
        return;
    };

    let (frame, l_off): (FrameState, u16) = inferred_join_frame();
    let local_tags: Vec<u8> = collapse_locals(&frame);
    let (class_bytes, tag_offsets): (Vec<u8>, Vec<usize>) = build_conv_class(&local_tags, l_off);

    let purpose: String = format!("disrobe_conv_frame_{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let root: PathBuf = scratch.path().to_path_buf();
    let ok_dir: PathBuf = root.join("ok");
    std::fs::create_dir_all(&ok_dir).expect("mkdir ok");

    let probe_src: PathBuf = ok_dir.join("Probe.java");
    std::fs::write(&probe_src, PROBE_SRC).expect("write probe");
    let compiled: std::process::Output = Command::new(&javac)
        .arg("-d")
        .arg(&ok_dir)
        .arg(&probe_src)
        .output()
        .expect("javac probe");
    assert!(
        compiled.status.success(),
        "probe did not compile: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    std::fs::write(ok_dir.join("Conv.class"), &class_bytes).expect("write Conv.class");
    let ok: std::process::Output = verify_dir(&java, &ok_dir);
    let ok_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&ok.stdout);
    eprintln!(
        "POSITIVE (StackMapTable from inferred frames): status={} stdout={} stderr={}",
        ok.status,
        ok_out.trim(),
        String::from_utf8_lossy(&ok.stderr).trim()
    );
    assert!(
        ok.status.success() && ok_out.contains("verify_ok=1"),
        "the class whose StackMapTable is built from the inferred conversion frame must pass \
         -Xverify:all; stderr:\n{}",
        String::from_utf8_lossy(&ok.stderr)
    );

    let conversion_slots: [(usize, u8, &str); 5] = [
        (
            3,
            0,
            "f2l result forced from Long to Top (the wrong single-slot push)",
        ),
        (4, 4, "f2d result forced from Double to Long"),
        (5, 2, "d2i result forced from Integer to Float"),
        (6, 3, "d2l result forced from Long to Double"),
        (7, 1, "d2f result forced from Float to Integer"),
    ];
    for (entry, bad_tag, label) in conversion_slots {
        let bad_dir: PathBuf = root.join(format!("bad_{entry}"));
        std::fs::create_dir_all(&bad_dir).expect("mkdir bad");
        std::fs::copy(ok_dir.join("Probe.class"), bad_dir.join("Probe.class")).expect("copy probe");
        let mut corrupt: Vec<u8> = class_bytes.clone();
        let off: usize = tag_offsets[entry];
        assert_ne!(
            corrupt[off], bad_tag,
            "the corrupted tag must differ from the correct one for slot entry {entry}"
        );
        corrupt[off] = bad_tag;
        std::fs::write(bad_dir.join("Conv.class"), &corrupt).expect("write bad Conv.class");
        let bad: std::process::Output = verify_dir(&java, &bad_dir);
        let bad_out: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad.stdout);
        let bad_err: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&bad.stderr);
        eprintln!(
            "NEGATIVE ({label}): status={} stdout={} stderr={}",
            bad.status,
            bad_out.trim(),
            bad_err.trim()
        );
        assert!(
            !bad.status.success() && !bad_out.contains("verify_ok=1"),
            "declaring the {label} in the StackMapTable must be rejected by the real JVM verifier; \
             the positive result would be vacuous if the verifier accepted a wrong conversion frame"
        );
        assert!(
            bad_err.contains("VerifyError")
                || bad_err.contains("StackMapTable")
                || bad_err.contains("ClassFormatError")
                || bad_err.contains("Bad")
                || bad_err.contains("bad type"),
            "the corrupted conversion frame must be rejected for a type/width mismatch; stderr:\n{bad_err}"
        );
    }
}
