use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn seed_replay_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_seed_replay"))
}

#[test]
fn mixed_target_process_replay_aggregates_reports_in_manifest_order()
-> core::result::Result<(), Box<dyn std::error::Error>> {
    let output: Output = Command::new(seed_replay_binary())
        .stdin(Stdio::null())
        .output()?;
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["schema"], 3usize);
    assert_eq!(report["obligations"]["satisfied"], 13usize);
    assert_eq!(report["obligations"]["declared"], 13usize);
    assert_eq!(report["obligations"]["positive_witnesses"], 9usize);
    assert_eq!(
        report["obligations"]["expected_rejection_witnesses"],
        4usize
    );
    let Some(targets): Option<&Vec<serde_json::Value>> = report["targets"].as_array() else {
        return Err("the process replay report has no target array".into());
    };
    assert_eq!(targets.len(), 2usize);
    assert_eq!(targets[0]["name"], "python_bytecode");
    assert_eq!(targets[0]["seeds"].as_array().map(Vec::len), Some(2usize));
    assert_eq!(targets[1]["name"], "dex_jvm_classfile");
    assert_eq!(targets[1]["seeds"].as_array().map(Vec::len), Some(4usize));

    let contract_path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("seed_reach.toml");
    let contract: disrobe_fuzz::seed_reach::SeedContract =
        disrobe_fuzz::seed_reach::SeedContract::read(&contract_path)?;
    let worker_output: Output = Command::new(seed_replay_binary())
        .args([
            "--worker",
            "--manifest-index",
            "2",
            "--contract-sha256",
            contract.sha256(),
        ])
        .stdin(Stdio::null())
        .output()?;
    assert!(worker_output.status.success());
    let fragment: serde_json::Value = serde_json::from_slice(&worker_output.stdout)?;
    assert_eq!(fragment["target"], "dex_jvm_classfile");
    assert_eq!(fragment["manifest_index"], 2usize);
    Ok(())
}
