use std::fs;
use std::path::{Path, PathBuf};

use disrobe_fuzz::dex_jvm_classfile;
use disrobe_fuzz::seed_reach::{
    ReplayObservations, ReplayOptions, ReplayTarget, ReplayTrace, SeedContract, SeedReachError,
    TargetReplay, replay_target, replay_target_with_options,
};
use disrobe_pass_jvm::{
    CaptureError, Captured, capture_observations, classfile::parse as parse_classfile,
    dex::parse_header,
};

#[derive(Debug)]
struct JvmReplay {
    capture: Captured<()>,
}

impl ReplayTrace for JvmReplay {
    fn observations(&self) -> ReplayObservations<'_> {
        ReplayObservations::Jvm(self.capture.observations())
    }
}

fn workspace_root() -> core::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let Some(root): Option<&Path> = fuzz_root.parent() else {
        return Err("the fuzz manifest has no workspace parent".into());
    };
    Ok(root.to_path_buf())
}

fn write_contract(
    name: &str,
    contents: &str,
) -> core::result::Result<(PathBuf, SeedContract), Box<dyn std::error::Error>> {
    let root: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-dex-jvm-seed-reach-{}-{name}",
        std::process::id()
    ));
    fs::create_dir_all(&root)?;
    let path: PathBuf = root.join("seed_reach.toml");
    fs::write(&path, contents)?;
    let contract: SeedContract = SeedContract::read(&path)?;
    Ok((root, contract))
}

fn replay_without_class_code_routes(data: &[u8]) -> Result<JvmReplay, CaptureError> {
    let capture: Captured<()> = capture_observations(|| {
        let _ = parse_classfile(data);
    })?;
    Ok(JvmReplay { capture })
}

fn replay_without_full_dex_routes(data: &[u8]) -> Result<JvmReplay, CaptureError> {
    let capture: Captured<()> = capture_observations(|| {
        let _ = parse_header(data);
    })?;
    Ok(JvmReplay { capture })
}

#[test]
fn real_class_code_routes_satisfy_their_parser_owned_obligations()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let contract_text: &str = r#"schema = 3

[[surface]]
target = "dex_jvm_classfile"
id = "jvm.class-file"
entry_point = "disrobe-pass-jvm/src/classfile.rs::parse"

[[surface]]
target = "dex_jvm_classfile"
id = "jvm.code-attribute"
entry_point = "disrobe-pass-jvm/src/bytecode.rs::parse_code_attribute"

[[surface]]
target = "dex_jvm_classfile"
id = "jvm.bytecode"
entry_point = "disrobe-pass-jvm/src/bytecode.rs::disassemble"

[[seed]]
target = "dex_jvm_classfile"
source = "corpus/jvm/stringer/StringerClassic.class"
offset = 0
length = 1641
sha256 = "b450d4d07fb685e57e53e34aab4816e42e0ec1358ece457da1368c51c3613b78"

[[seed.obligation]]
surface = "jvm.class-file"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1

[[seed.obligation]]
surface = "jvm.code-attribute"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1

[[seed.obligation]]
surface = "jvm.bytecode"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1
"#;
    let (temporary_root, contract): (PathBuf, SeedContract) =
        write_contract("current-class-route", contract_text)?;
    let replay: TargetReplay = replay_target(
        &workspace_root()?,
        &contract,
        ReplayTarget::DexJvmClassfile,
        dex_jvm_classfile::replay,
    )?;
    fs::remove_dir_all(&temporary_root)?;

    assert_eq!(replay.satisfied_obligations(), 3usize);
    Ok(())
}

#[test]
fn real_dex_routes_satisfy_header_model_and_code_item_obligations()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let contract_text: &str = r#"schema = 3

[[surface]]
target = "dex_jvm_classfile"
id = "android.dex.header"
entry_point = "disrobe-pass-jvm/src/dex.rs::parse_header"

[[surface]]
target = "dex_jvm_classfile"
id = "android.dex.file"
entry_point = "disrobe-pass-jvm/src/dex.rs::parse"

[[surface]]
target = "dex_jvm_classfile"
id = "android.dex.code-items"
entry_point = "disrobe-pass-jvm/src/dex.rs::parse_code_items"

[[seed]]
target = "dex_jvm_classfile"
source = "corpus/jvm/dex/Hello.dex"
offset = 0
length = 1660
sha256 = "4057e61e1df4a583690a5f7f0b0ecc8db0c6f2c4676c78978aeafda7be1256f8"

[[seed.obligation]]
surface = "android.dex.header"
outcome = "accepted"
minimum_bytes = 112
minimum_items = 1

[[seed.obligation]]
surface = "android.dex.file"
outcome = "accepted"
minimum_bytes = 112
minimum_items = 1

[[seed.obligation]]
surface = "android.dex.code-items"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1
"#;
    let (temporary_root, contract): (PathBuf, SeedContract) =
        write_contract("real-dex-route", contract_text)?;
    let replay: TargetReplay = replay_target(
        &workspace_root()?,
        &contract,
        ReplayTarget::DexJvmClassfile,
        dex_jvm_classfile::replay,
    )?;
    fs::remove_dir_all(&temporary_root)?;

    assert_eq!(replay.satisfied_obligations(), 3usize);
    assert_eq!(replay.positive_witnesses(), 3usize);
    Ok(())
}

#[test]
fn committed_jvm_contract_replays_through_the_shared_exercise()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;
    let replay: TargetReplay = replay_target(
        &workspace_root()?,
        &contract,
        ReplayTarget::DexJvmClassfile,
        dex_jvm_classfile::replay,
    )?;

    assert_eq!(replay.seed_count(), 4usize);
    assert_eq!(replay.satisfied_obligations(), 9usize);
    assert_eq!(replay.declared_obligations(), 9usize);
    assert_eq!(replay.positive_witnesses(), 6usize);
    assert_eq!(replay.expected_rejection_witnesses(), 3usize);
    assert_eq!(replay.canonical_trace_runs(), 4usize);
    Ok(())
}

#[test]
fn shuffled_parallel_jvm_replay_is_byte_identical_to_manifest_order()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let fuzz_root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let contract: SeedContract = SeedContract::read(&fuzz_root.join("seed_reach.toml"))?;
    let sequential: TargetReplay = replay_target_with_options(
        &workspace_root()?,
        &contract,
        ReplayTarget::DexJvmClassfile,
        dex_jvm_classfile::replay,
        ReplayOptions {
            jobs: 1,
            order_seed: 0,
        },
    )?;
    let parallel: TargetReplay = replay_target_with_options(
        &workspace_root()?,
        &contract,
        ReplayTarget::DexJvmClassfile,
        dex_jvm_classfile::replay,
        ReplayOptions {
            jobs: 4,
            order_seed: 0x4a56_4d44_4558,
        },
    )?;

    assert_eq!(sequential.canonical_json()?, parallel.canonical_json()?);
    Ok(())
}

#[test]
fn the_fuzz_target_exercises_each_jvm_mutation_once() {
    let invocation_count: core::cell::Cell<usize> = core::cell::Cell::new(0usize);
    let outcome: &[u8] = dex_jvm_classfile::run_fuzz_input(b"mutation", |data: &[u8]| {
        invocation_count.set(invocation_count.get().saturating_add(1));
        data
    });
    assert_eq!(outcome, b"mutation");
    assert_eq!(invocation_count.get(), 1usize);

    let target_source: &str = include_str!("../fuzz_targets/dex_jvm_classfile.rs");
    assert!(target_source.contains("dex_jvm_classfile::run_fuzz_input"));
    assert_eq!(
        target_source.matches("dex_jvm_classfile::exercise").count(),
        1usize
    );
    assert!(!target_source.contains("dex_jvm_classfile::replay"));
}

#[test]
fn removing_real_code_attribute_traversal_fails_the_class_code_obligation()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let contract_text: &str = r#"schema = 3

[[surface]]
target = "dex_jvm_classfile"
id = "jvm.code-attribute"
entry_point = "disrobe-pass-jvm/src/bytecode.rs::parse_code_attribute"

[[surface]]
target = "dex_jvm_classfile"
id = "jvm.bytecode"
entry_point = "disrobe-pass-jvm/src/bytecode.rs::disassemble"

[[seed]]
target = "dex_jvm_classfile"
source = "corpus/jvm/stringer/StringerClassic.class"
offset = 0
length = 1641
sha256 = "b450d4d07fb685e57e53e34aab4816e42e0ec1358ece457da1368c51c3613b78"

[[seed.obligation]]
surface = "jvm.code-attribute"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1

[[seed.obligation]]
surface = "jvm.bytecode"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1
"#;
    let (temporary_root, contract): (PathBuf, SeedContract) =
        write_contract("class-route-removal", contract_text)?;
    let result: Result<TargetReplay, SeedReachError> = replay_target(
        &workspace_root()?,
        &contract,
        ReplayTarget::DexJvmClassfile,
        replay_without_class_code_routes,
    );
    fs::remove_dir_all(&temporary_root)?;

    assert!(
        matches!(result, Err(SeedReachError::Invalid(message)) if message.contains("jvm.code-attribute"))
    );
    Ok(())
}

#[test]
fn removing_full_dex_parse_fails_while_the_header_route_remains()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let contract_text: &str = r#"schema = 3

[[surface]]
target = "dex_jvm_classfile"
id = "android.dex.file"
entry_point = "disrobe-pass-jvm/src/dex.rs::parse"

[[surface]]
target = "dex_jvm_classfile"
id = "android.dex.code-items"
entry_point = "disrobe-pass-jvm/src/dex.rs::parse_code_items"

[[seed]]
target = "dex_jvm_classfile"
source = "corpus/jvm/dex/Hello.dex"
offset = 0
length = 1660
sha256 = "4057e61e1df4a583690a5f7f0b0ecc8db0c6f2c4676c78978aeafda7be1256f8"

[[seed.obligation]]
surface = "android.dex.file"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1

[[seed.obligation]]
surface = "android.dex.code-items"
outcome = "accepted"
minimum_bytes = 1
minimum_items = 1
"#;
    let (temporary_root, contract): (PathBuf, SeedContract) =
        write_contract("dex-route-removal", contract_text)?;
    let result: Result<TargetReplay, SeedReachError> = replay_target(
        &workspace_root()?,
        &contract,
        ReplayTarget::DexJvmClassfile,
        replay_without_full_dex_routes,
    );
    fs::remove_dir_all(&temporary_root)?;

    assert!(
        matches!(result, Err(SeedReachError::Invalid(message)) if message.contains("android.dex.file"))
    );
    Ok(())
}
