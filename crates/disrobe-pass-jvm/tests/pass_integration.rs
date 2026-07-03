#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_core::{Artifact, Capability, LegacyPass, PassMetadata, Rung};
use disrobe_pass_jvm::JvmPass;

#[test]
fn pass_id_is_stable() {
    let p: JvmPass = JvmPass::new();
    assert_eq!(PassMetadata::id(&p), "jvm.deob");
}

fn minimal_classfile(major: u16) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&0xCAFE_BABE_u32.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&major.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes());
    for _ in 0..7 {
        buf.extend_from_slice(&0u16.to_be_bytes());
    }
    buf
}

#[test]
fn pass_promotes_raw_to_disasm() {
    let input: Artifact = Artifact::new(Rung::Raw, minimal_classfile(52), [0u8; 32]);
    let output: Artifact = JvmPass::new().run(&input).expect("valid classfile parses");
    assert_eq!(output.rung, Rung::Disasm);
    let names: Vec<&str> = output
        .capabilities
        .iter()
        .map(|c: &Capability| c.name.as_str())
        .collect();
    assert_eq!(
        names.len(),
        11,
        "the jvm pass advertises its full produced-capability set, got {names:?}"
    );
    for want in [
        "jvm.classfile",
        "jvm.dex",
        "android.apk.resources",
        "android.arsc",
    ] {
        assert!(
            names.contains(&want),
            "produced capabilities must include {want:?}, got {names:?}"
        );
    }
}
