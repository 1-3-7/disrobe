#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_core::{Artifact, LegacyPass, PassMetadata, Rung};
use disrobe_pass_jvm::JvmPass;

#[test]
fn pass_id_is_stable() {
    let p: JvmPass = JvmPass::new();
    assert_eq!(PassMetadata::id(&p), "jvm.deob");
}

#[test]
fn pass_promotes_raw_to_disasm() {
    let input: Artifact = Artifact::new(Rung::Raw, vec![0, 1, 2], [0u8; 32]);
    let output: Artifact = JvmPass::new().run(&input).expect("ok");
    assert_eq!(output.rung, Rung::Disasm);
    assert_eq!(output.capabilities.len(), 4);
}
