use std::ffi::OsStr;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use disrobe_core::recon::{ReconConfig, ReconFinding, ReconReport, report_tree};
use disrobe_core::scratch::ScratchDir;
use eyre::{Result, WrapErr, bail};
use serde_json::{Value, json};

use crate::apkleaks_capture;
use crate::tool::{
    MAX_FIXTURE_BYTES, MAX_TEXT_BYTES, MAX_ZIP_ENTRIES, MAX_ZIP_ENTRY_BYTES, MAX_ZIP_TOTAL_BYTES,
    ToolInvocation, VersionCapture, find_on_path, read_bounded_file, read_bounded_string,
    require_pinned_version, require_success, retain_tool_provenance, run_with_env,
    version_capture_checked, version_capture_with_env_checked, version_of_checked,
    version_of_usage_checked,
};

struct PlantedSecret {
    label: &'static str,
    token_parts: &'static [&'static str],
}

impl PlantedSecret {
    fn token(&self) -> String {
        self.token_parts.concat()
    }
}

const GROUND_TRUTH: &[PlantedSecret] = &[
    PlantedSecret {
        label: "AWS access key id",
        token_parts: &["AKIA", "3KFTG2KQ4WXYZ7AB"],
    },
    PlantedSecret {
        label: "AWS secret access key",
        token_parts: &["wJalrXUtnFEMI", "K7MDENGbPxRfiCYz9Qd2RtBvHnP"],
    },
    PlantedSecret {
        label: "Google OAuth access token",
        token_parts: &["ya29.", "AbCdEf0123456789ghijklmnopqr"],
    },
    PlantedSecret {
        label: "GCP / Google Maps API key",
        token_parts: &["AIza", "SyA0123456789abcdefghijklmnopqrstuv"],
    },
    PlantedSecret {
        label: "HTTP Basic auth credential",
        token_parts: &["YWRtaW46czNjcjN0", "UEBzc3cwcmRWYWx1ZQ=="],
    },
    PlantedSecret {
        label: "session JWT",
        token_parts: &["eyJhbGciOiJIUzI1NiIsInR5cCI6", "IkpXVCJ9"],
    },
    PlantedSecret {
        label: "Firebase database URL",
        token_parts: &["planted-app-9921.", "firebaseio.com"],
    },
    PlantedSecret {
        label: "S3 bucket URL",
        token_parts: &["planted-uploads.", "s3.amazonaws.com"],
    },
];

pub fn measure(root: &Path, run_dir: &Path) -> Result<(String, Value)> {
    let id: String = "frisk-apkleaks".to_owned();
    let apk: PathBuf = root
        .join("corpus")
        .join("recon")
        .join("apk")
        .join("planted-secrets.apk");
    if !apk.is_file() {
        bail!(
            "{} is committed and both tools read it; without it neither side of this row is \
             measured against anything",
            apk.display()
        );
    }
    let apk_bytes: Vec<u8> = read_bounded_file(&apk, MAX_FIXTURE_BYTES)
        .wrap_err_with(|| format!("reading {}", apk.display()))?;
    let frisk_run_dir: PathBuf = run_dir.join("frisk-apkleaks");
    std::fs::create_dir(&frisk_run_dir).wrap_err_with(|| {
        format!(
            "creating unique frisk artifact directory {}",
            frisk_run_dir.display()
        )
    })?;
    let tree_work: ScratchDir =
        ScratchDir::create("disrobe_h2h_frisk").wrap_err("creating frisk scratch directory")?;
    let tree: PathBuf = tree_work.path().to_path_buf();
    extract_apk(&apk_bytes, &tree)?;

    let disrobe_report: ReconReport = report_tree(&tree, &ReconConfig::default())
        .map_err(|error| eyre::eyre!("disrobe frisk scan failed: {error}"))?;
    let disrobe_hits: Vec<usize> = recall_indices_disrobe(&disrobe_report);
    let report_sha256: String = retain_recon_report(&frisk_run_dir, &disrobe_report)
        .map_err(|error: String| eyre::eyre!(error))?;
    let mut disrobe_tool: Value = tool_json(
        "disrobe frisk (in-process recon engine)",
        "n/a (in-process)",
        &disrobe_hits,
        "ok",
        None,
    );
    disrobe_tool["recon_report_artifact"] =
        Value::String("frisk-apkleaks/disrobe/recon-report.json".to_owned());
    disrobe_tool["recon_report_sha256"] = Value::String(report_sha256);
    let apkleaks_result: ApkleaksResult = run_apkleaks(root, &apk, &frisk_run_dir);
    require_live_apkleaks(&apkleaks_result).map_err(|error: String| eyre::eyre!(error))?;
    let (apkleaks_hits, apkleaks_tool): (Vec<usize>, Value) =
        retain_apkleaks_measurement(&apkleaks_result, &frisk_run_dir)?;

    tree_work
        .close()
        .wrap_err("cleaning frisk scratch directory")?;

    let tools: Vec<Value> = vec![disrobe_tool, apkleaks_tool];
    let ground: Vec<Value> = GROUND_TRUTH
        .iter()
        .map(|s: &PlantedSecret| {
            json!({
                "label": s.label,
                "found_by_disrobe": disrobe_hits.contains(&secret_index(s)),
                "found_by_apkleaks": apkleaks_hits.contains(&secret_index(s)),
            })
        })
        .collect();

    let value: Value = json!({
        "id": id,
        "title": "Secret recall: disrobe frisk and APKLeaks",
        "status": "ok",
        "ecosystem": "secrets",
        "dataset": "corpus/recon/apk/planted-secrets.apk contains 8 planted secrets across smali, res/raw, res/values, and assets",
        "oracle": "exact-token recall against the same 8 planted secrets for both tools",
        "denominator": format!("{} planted high-value secrets (fixed, identical for both tools)", GROUND_TRUTH.len()),
        "reproduce": "cargo run --locked -p disrobe-bench-head-to-head -- --check --only frisk-apkleaks",
        "fairness": [
            "identical input bytes: both tools scan the byte-identical committed planted-secrets.apk",
            "same oracle: recall against the same 8-secret planted ground truth",
            "fixed shared denominator: the count of planted secrets",
            "apkleaks finding nothing counts as zero recall; a missing or failed live tool fails regeneration",
            "apkleaks runs its own jadx-then-regex flow; disrobe frisk scans the extracted member tree (its real product path)"
        ],
        "ground_truth": ground,
        "tools": tools,
        "honest_note": honest_note(&tools, &apkleaks_hits),
    });
    Ok((id, value))
}

fn retain_apkleaks_measurement(
    result: &ApkleaksResult,
    run_dir: &Path,
) -> Result<(Vec<usize>, Value)> {
    match result {
        ApkleaksResult::Ok {
            version,
            hits,
            via,
            raw_json_sha256,
            jadx_version,
            jadx_executable,
            jadx_executable_sha256,
        } => {
            let report_sha256: String = retain_apkleaks_report(
                &run_dir.join("apkleaks"),
                raw_json_sha256,
                jadx_executable,
                jadx_executable_sha256,
            )?;
            let detail: String = apkleaks_measurement_detail(via, &report_sha256);
            let mut tool: Value = tool_json("apkleaks", version, hits, "ok", Some(detail.as_str()));
            tool["execution_route"] = Value::String(via.clone());
            tool["raw_json_artifact"] =
                Value::String("frisk-apkleaks/apkleaks/apkleaks.json".to_owned());
            tool["lf_json_artifact"] =
                Value::String("frisk-apkleaks/apkleaks/apkleaks.lf.json".to_owned());
            tool["lf_json_sha256"] = Value::String(report_sha256);
            tool["report_provenance_artifact"] =
                Value::String("frisk-apkleaks/apkleaks/report-provenance.json".to_owned());
            tool["jadx_version"] = Value::String(jadx_version.clone());
            tool["jadx_provenance_artifact"] =
                Value::String("frisk-apkleaks/apkleaks/jadx/provenance.json".to_owned());
            Ok((hits.clone(), tool))
        }
        ApkleaksResult::Skipped(reason) => bail!("apkleaks was unavailable: {reason}"),
        ApkleaksResult::Error { version, reason } => {
            bail!("apkleaks `{version}` failed: {reason}")
        }
    }
}

fn apkleaks_measurement_detail(execution_route: &str, lf_json_sha256: &str) -> String {
    format!(
        "live apkleaks 2.6.3 planted-secret membership via {execution_route}; LF-normalized JSON SHA-256 {lf_json_sha256}; original JSON bytes, their checksum, launcher provenance, and process streams are retained in this run's durable artifact directory"
    )
}

fn retain_apkleaks_report(
    artifact_dir: &Path,
    expected_raw_sha256: &str,
    jadx_executable: &Path,
    jadx_executable_sha256: &str,
) -> Result<String> {
    let raw: String = read_bounded_string(&artifact_dir.join("apkleaks.json"), MAX_TEXT_BYTES)
        .wrap_err("reading retained APKLeaks JSON")?;
    let raw_sha256: String = apkleaks_capture::sha256_hex(raw.as_bytes());
    if raw_sha256 != expected_raw_sha256 {
        bail!(
            "retained APKLeaks JSON differs from the graded report: expected {expected_raw_sha256}, got {raw_sha256}"
        );
    }
    let normalized: String = raw.replace("\r\n", "\n");
    let digest: String = apkleaks_capture::sha256_hex(normalized.as_bytes());
    let provenance: Value = json!({
        "raw_json_artifact": "apkleaks.json",
        "raw_json_sha256": raw_sha256,
        "raw_json_bytes": raw.len(),
        "lf_json_artifact": "apkleaks.lf.json",
        "lf_json_sha256": digest,
        "lf_json_bytes": normalized.len(),
        "normalization": "replace CRLF line endings with LF; preserve every other byte",
        "jadx_executable": jadx_executable,
        "jadx_executable_sha256": jadx_executable_sha256,
        "jadx_provenance_artifact": "jadx/provenance.json",
    });
    let provenance_bytes: Vec<u8> = serde_json::to_vec_pretty(&provenance)
        .wrap_err("serializing APKLeaks report provenance")?;
    std::fs::write(artifact_dir.join("apkleaks.lf.json"), normalized)
        .wrap_err("retaining LF-normalized APKLeaks report")?;
    std::fs::write(
        artifact_dir.join("report-provenance.json"),
        provenance_bytes,
    )
    .wrap_err("retaining APKLeaks report provenance")?;
    Ok(digest)
}

fn secret_index(target: &PlantedSecret) -> usize {
    GROUND_TRUTH
        .iter()
        .position(|s: &PlantedSecret| s.label == target.label)
        .unwrap_or(usize::MAX)
}

fn recall_indices_disrobe(report: &ReconReport) -> Vec<usize> {
    GROUND_TRUTH
        .iter()
        .enumerate()
        .filter_map(|(i, s): (usize, &PlantedSecret)| {
            let token: String = s.token();
            let exact_token: bool = report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.value.contains(&token));
            exact_token.then_some(i)
        })
        .collect()
}

fn retain_recon_report(run_dir: &Path, report: &ReconReport) -> Result<String, String> {
    let artifact_dir: PathBuf = run_dir.join("disrobe");
    std::fs::create_dir(&artifact_dir)
        .map_err(|error| format!("creating disrobe frisk artifact directory: {error}"))?;
    let mut raw: Vec<u8> = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("serializing disrobe frisk report: {error}"))?;
    raw.push(b'\n');
    let mut normalized: ReconReport = report.clone();
    normalized.root = Some("planted-secrets.apk!/".to_owned());
    let mut stable: Vec<u8> = serde_json::to_vec_pretty(&normalized)
        .map_err(|error| format!("serializing portable disrobe frisk report: {error}"))?;
    stable.push(b'\n');
    if [raw.len(), stable.len()]
        .into_iter()
        .any(|len: usize| u64::try_from(len).map_or(true, |size: u64| size > MAX_TEXT_BYTES))
    {
        return Err(format!(
            "serialized disrobe frisk report exceeds {MAX_TEXT_BYTES} bytes"
        ));
    }
    let digest: String = apkleaks_capture::sha256_hex(&stable);
    let provenance: Value = json!({
        "raw_report": "recon-report.raw.json",
        "raw_report_sha256": apkleaks_capture::sha256_hex(&raw),
        "report": "recon-report.json",
        "report_sha256": digest,
        "root_mapping": {"physical": report.root, "logical": normalized.root},
    });
    let provenance_bytes: Vec<u8> = serde_json::to_vec_pretty(&provenance)
        .map_err(|error| format!("serializing disrobe frisk provenance: {error}"))?;
    std::fs::write(artifact_dir.join("recon-report.raw.json"), &raw)
        .map_err(|error| format!("retaining raw disrobe frisk report: {error}"))?;
    std::fs::write(artifact_dir.join("recon-report.json"), &stable)
        .map_err(|error| format!("retaining disrobe frisk report: {error}"))?;
    std::fs::write(artifact_dir.join("provenance.json"), provenance_bytes)
        .map_err(|error| format!("retaining disrobe frisk provenance: {error}"))?;
    Ok(digest)
}

fn tool_json(
    name: &str,
    version: &str,
    hits: &[usize],
    status: &str,
    error: Option<&str>,
) -> Value {
    let found: usize = hits.len();
    let total: usize = GROUND_TRUTH.len();
    let pct: f64 = 100.0 * found as f64 / total.max(1) as f64;
    let mut v: serde_json::Map<String, Value> = serde_json::Map::new();
    v.insert("name".to_owned(), json!(name));
    v.insert("version".to_owned(), json!(version));
    v.insert("metric".to_owned(), json!("recall %"));
    v.insert("value".to_owned(), json!(pct));
    v.insert("found".to_owned(), json!(found));
    v.insert("total".to_owned(), json!(total));
    v.insert(
        "display".to_owned(),
        json!(format!("{found}/{total} ({pct:.1}%)")),
    );
    v.insert("status".to_owned(), json!(status));
    if let Some(e) = error {
        v.insert("detail".to_owned(), json!(e));
    }
    Value::Object(v)
}

fn honest_note(tools: &[Value], apkleaks_hits: &[usize]) -> String {
    let disrobe: Option<f64> = tools
        .iter()
        .find(|t: &&Value| {
            t.get("name")
                .and_then(Value::as_str)
                .is_some_and(|n: &str| n.starts_with("disrobe"))
        })
        .and_then(|t: &Value| t.get("value").and_then(Value::as_f64));
    let apkleaks_tool: Option<&Value> = tools.iter().find(|t: &&Value| {
        t.get("name")
            .and_then(Value::as_str)
            .is_some_and(|n: &str| n.starts_with("apkleaks"))
    });
    let apkleaks_status: Option<&str> =
        apkleaks_tool.and_then(|t: &Value| t.get("status").and_then(Value::as_str));
    match (disrobe, apkleaks_status) {
        (Some(d), Some("ok")) => {
            let a: f64 = apkleaks_tool
                .and_then(|t: &Value| t.get("value").and_then(Value::as_f64))
                .unwrap_or(0.0);
            if d >= a {
                let misses: Vec<&str> = GROUND_TRUTH
                    .iter()
                    .enumerate()
                    .filter_map(|(index, secret): (usize, &PlantedSecret)| {
                        (!apkleaks_hits.contains(&index)).then_some(secret.label)
                    })
                    .collect();
                let miss_detail: String = if misses.is_empty() {
                    "apkleaks matched every planted token".to_owned()
                } else {
                    format!("apkleaks did not match: {}", misses.join(", "))
                };
                format!(
                    "`disrobe frisk` recalls {d:.1}% of the planted secrets; apkleaks recalls \
                     {a:.1}%. {miss_detail}. This row scores only the shared 8-secret ground truth."
                )
            } else {
                format!(
                    "apkleaks recalls {a:.1}% vs `disrobe frisk` {d:.1}% on this APK. Published as \
                     the honest measured result; the residual is a gap to close in the frisk rule \
                     set."
                )
            }
        }
        (Some(d), _) => format!(
            "`disrobe frisk` recalls {d:.1}% of the planted secrets. apkleaks did not produce a \
             comparable result on this box; the captured status records the reason."
        ),
        _ => "Neither tool produced a scorable result on this box.".to_owned(),
    }
}

enum ApkleaksResult {
    Ok {
        version: String,
        hits: Vec<usize>,
        via: String,
        raw_json_sha256: String,
        jadx_version: String,
        jadx_executable: PathBuf,
        jadx_executable_sha256: String,
    },
    Skipped(String),
    Error {
        version: String,
        reason: String,
    },
}

struct ApkleaksJadx {
    executable: PathBuf,
    version: VersionCapture,
    executable_sha256: String,
    java_home: PathBuf,
}

fn jadx_search_prefix(selected: &Path) -> Result<String, String> {
    let path: &str = selected
        .to_str()
        .ok_or_else(|| "the selected JADX directory is not Unicode".to_owned())?;
    #[cfg(windows)]
    {
        let normalized: String = path.replace('\\', "/");
        if normalized.is_empty()
            || !normalized.bytes().all(|byte: u8| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
            })
        {
            return Err(
                "APKLeaks 2.6.3 requires a Windows JADX path without spaces or shell characters"
                    .to_owned(),
            );
        }
        Ok(format!("{}/", normalized.trim_end_matches('/')))
    }
    #[cfg(not(windows))]
    {
        Ok(path.to_owned())
    }
}

fn prefixed_search_path(selected: &Path, inherited: &OsStr) -> Result<String, String> {
    let prefix: String = jadx_search_prefix(selected)?;
    #[cfg(windows)]
    {
        let inherited: &str = inherited
            .to_str()
            .ok_or_else(|| "the inherited PATH is not Unicode".to_owned())?;
        Ok(format!("{prefix};{inherited}"))
    }
    #[cfg(not(windows))]
    {
        let entries: Vec<PathBuf> = std::iter::once(PathBuf::from(prefix))
            .chain(std::env::split_paths(inherited))
            .collect();
        std::env::join_paths(entries)
            .map_err(|error| format!("constructing the JADX-prefixed PATH: {error}"))?
            .into_string()
            .map_err(|_| "the JADX-prefixed PATH is not Unicode".to_owned())
    }
}

fn run_apkleaks(root: &Path, apk: &Path, run_dir: &Path) -> ApkleaksResult {
    let Some(apkleaks): Option<PathBuf> = find_on_path("apkleaks") else {
        return ApkleaksResult::Skipped("apkleaks not on PATH".to_owned());
    };
    let version: VersionCapture = match version_capture_checked(&apkleaks, &["--version"], Some(2))
    {
        Ok(version) => version,
        Err(reason) => {
            return ApkleaksResult::Error {
                version: "unavailable".to_owned(),
                reason,
            };
        }
    };
    let display: String = version.display.clone();
    if let Err(reason) = require_pinned_version(root, "apkleaks", &display) {
        return ApkleaksResult::Error {
            version: display,
            reason,
        };
    }
    let Some(jadx): Option<PathBuf> = find_on_path("jadx") else {
        return ApkleaksResult::Error {
            version: display,
            reason: "jadx is not on PATH".to_owned(),
        };
    };
    let Some(java): Option<PathBuf> = find_on_path("java") else {
        return ApkleaksResult::Error {
            version: display,
            reason: "java is not on PATH".to_owned(),
        };
    };
    let Some(java_home): Option<PathBuf> = java.parent().and_then(Path::parent).map(Path::to_owned)
    else {
        return ApkleaksResult::Error {
            version: display,
            reason: format!("selected java path has no JDK root: {}", java.display()),
        };
    };
    let Some(jadx_parent): Option<&Path> = jadx.parent() else {
        return ApkleaksResult::Error {
            version: display,
            reason: format!("selected JADX path has no parent: {}", jadx.display()),
        };
    };
    let java_home_value: String = java_home.to_string_lossy().into_owned();
    let Some(inherited_path) = std::env::var_os("PATH") else {
        return ApkleaksResult::Error {
            version: display,
            reason: "PATH disappeared after resolving JADX".to_owned(),
        };
    };
    let execution_path: String = match prefixed_search_path(jadx_parent, &inherited_path) {
        Ok(path) => path,
        Err(reason) => {
            return ApkleaksResult::Error {
                version: display,
                reason,
            };
        }
    };
    let version_environment: [(&str, &str); 2] = [
        ("PATH", execution_path.as_str()),
        ("JAVA_HOME", java_home_value.as_str()),
    ];
    let jadx_version: VersionCapture =
        match version_capture_with_env_checked(&jadx, &["--version"], &version_environment, None) {
            Ok(version) => version,
            Err(reason) => {
                return ApkleaksResult::Error {
                    version: display,
                    reason: format!("probing the JADX selected for apkleaks: {reason}"),
                };
            }
        };
    if let Err(reason) = require_pinned_version(root, "jadx", &jadx_version.display) {
        return ApkleaksResult::Error {
            version: display,
            reason,
        };
    }
    let jadx_bytes: Vec<u8> = match read_bounded_file(&jadx, MAX_FIXTURE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return ApkleaksResult::Error {
                version: display,
                reason: format!("hashing the JADX selected for apkleaks: {error}"),
            };
        }
    };
    let resolved: ApkleaksJadx = ApkleaksJadx {
        executable: jadx,
        version: jadx_version,
        executable_sha256: apkleaks_capture::sha256_hex(&jadx_bytes),
        java_home,
    };
    select_apkleaks_result(
        display,
        apkleaks_cli(&apkleaks, apk, run_dir, &version, &resolved),
    )
}

pub fn require_pinned_versions(root: &Path) -> Result<(), String> {
    let apkleaks: PathBuf =
        find_on_path("apkleaks").ok_or_else(|| "apkleaks is not on PATH".to_owned())?;
    let version: String = version_of_usage_checked(&apkleaks, &["--version"], 2)?;
    require_pinned_version(root, "apkleaks", &version)?;
    let jadx: PathBuf = find_on_path("jadx").ok_or_else(|| "jadx is not on PATH".to_owned())?;
    let version: String = version_of_checked(&jadx, &["--version"])?;
    require_pinned_version(root, "jadx", &version)?;
    Ok(())
}

fn require_live_apkleaks(result: &ApkleaksResult) -> Result<(), String> {
    match result {
        ApkleaksResult::Ok { via, .. } if via == "cli" => Ok(()),
        ApkleaksResult::Ok { via, .. } => {
            Err(format!("required apkleaks used the {via} fallback route"))
        }
        ApkleaksResult::Skipped(reason) => Err(format!("required apkleaks was skipped: {reason}")),
        ApkleaksResult::Error { reason, .. } => Err(format!("required apkleaks failed: {reason}")),
    }
}

enum ApkleaksCliResult {
    Ok {
        hits: Vec<usize>,
        raw_json_sha256: String,
        jadx_version: String,
        jadx_executable: PathBuf,
        jadx_executable_sha256: String,
    },
    Failed(String),
}

fn select_apkleaks_result(version: String, cli: ApkleaksCliResult) -> ApkleaksResult {
    match cli {
        ApkleaksCliResult::Ok {
            hits,
            raw_json_sha256,
            jadx_version,
            jadx_executable,
            jadx_executable_sha256,
        } => ApkleaksResult::Ok {
            version,
            hits,
            via: "cli".to_owned(),
            raw_json_sha256,
            jadx_version,
            jadx_executable,
            jadx_executable_sha256,
        },
        ApkleaksCliResult::Failed(reason) => ApkleaksResult::Error { version, reason },
    }
}

fn apkleaks_cli(
    apkleaks: &Path,
    apk: &Path,
    run_dir: &Path,
    version: &VersionCapture,
    jadx: &ApkleaksJadx,
) -> ApkleaksCliResult {
    let out_dir: PathBuf = run_dir.join("apkleaks");
    if let Err(error) = std::fs::create_dir(&out_dir) {
        return ApkleaksCliResult::Failed(format!(
            "creating unique apkleaks artifact directory {} failed: {error}",
            out_dir.display()
        ));
    }
    let parsed: core::result::Result<(Vec<usize>, String), String> = (|| {
        let out_json: PathBuf = out_dir.join("apkleaks.json");
        let apk_str: String = apk.to_string_lossy().into_owned();
        let out_str: String = out_json.to_string_lossy().into_owned();
        let invocation_args: Vec<String> = vec![
            "-f".to_owned(),
            apk_str.clone(),
            "-o".to_owned(),
            out_str.clone(),
            "--json".to_owned(),
        ];
        let apk_bytes: Vec<u8> = read_bounded_file(apk, MAX_FIXTURE_BYTES)
            .map_err(|error| format!("hashing apkleaks input: {error}"))?;
        let input_hashes: Vec<(String, String)> = vec![(
            "planted-secrets.apk".to_owned(),
            apkleaks_capture::sha256_hex(&apk_bytes),
        )];
        let selected_path: String = jadx_search_prefix(
            jadx.executable
                .parent()
                .ok_or_else(|| "selected JADX path has no parent directory".to_owned())?,
        )?;
        let java_home: String = jadx.java_home.to_string_lossy().into_owned();
        let inherited_path: std::ffi::OsString = std::env::var_os("PATH")
            .ok_or_else(|| "PATH disappeared before invoking apkleaks".to_owned())?;
        let execution_path: String = prefixed_search_path(
            jadx.executable
                .parent()
                .ok_or_else(|| "selected JADX path has no parent directory".to_owned())?,
            &inherited_path,
        )?;
        let environment_metadata: [(&str, &str); 2] = [
            ("JADX_PATH_PREFIX", selected_path.as_str()),
            ("JAVA_HOME", java_home.as_str()),
        ];
        let jadx_dir: PathBuf = out_dir.join("jadx");
        std::fs::create_dir(&jadx_dir)
            .map_err(|error| format!("creating retained JADX provenance directory: {error}"))?;
        let jadx_args: Vec<String> = vec!["--version".to_owned()];
        retain_tool_provenance(
            &jadx_dir,
            &ToolInvocation {
                route: "apkleaks PATH selection",
                executable: &jadx.executable,
                args: &jadx_args,
                environment: &environment_metadata,
                output: Some(&jadx.version.output),
            },
            &["--version"],
            &jadx.version,
            &input_hashes,
        )?;
        let environment: [(&str, &str); 4] = [
            ("PYTHONUTF8", "1"),
            ("PYTHONIOENCODING", "utf-8"),
            ("PATH", execution_path.as_str()),
            ("JAVA_HOME", java_home.as_str()),
        ];
        let output: disrobe_core::subprocess::CapturedOutput = match run_with_env(
            apkleaks,
            &["-f", &apk_str, "-o", &out_str, "--json"],
            &environment,
        ) {
            Ok(output) => output,
            Err(error) => {
                retain_tool_provenance(
                    &out_dir,
                    &ToolInvocation {
                        route: "cli",
                        executable: apkleaks,
                        args: &invocation_args,
                        environment: &environment_metadata,
                        output: None,
                    },
                    &["--version"],
                    version,
                    &input_hashes,
                )?;
                return Err(format!("running apkleaks: {error}"));
            }
        };
        retain_tool_provenance(
            &out_dir,
            &ToolInvocation {
                route: "cli",
                executable: apkleaks,
                args: &invocation_args,
                environment: &environment_metadata,
                output: Some(&output),
            },
            &["--version"],
            version,
            &input_hashes,
        )?;
        let _: disrobe_core::subprocess::CapturedOutput = require_success(output, "apkleaks")?;
        let raw: String =
            read_bounded_string(&out_json, MAX_TEXT_BYTES).map_err(|error| error.to_string())?;
        let hits: Vec<usize> = recall_indices_apkleaks(&raw)
            .ok_or_else(|| "apkleaks JSON did not match the expected result shape".to_owned())?;
        Ok((hits, apkleaks_capture::sha256_hex(raw.as_bytes())))
    })();
    match parsed {
        Ok((hits, raw_json_sha256)) => ApkleaksCliResult::Ok {
            hits,
            raw_json_sha256,
            jadx_version: jadx.version.display.clone(),
            jadx_executable: jadx.executable.clone(),
            jadx_executable_sha256: jadx.executable_sha256.clone(),
        },
        Err(reason) => ApkleaksCliResult::Failed(reason),
    }
}

fn recall_indices_apkleaks(raw: &str) -> Option<Vec<usize>> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let results: &Vec<Value> = v.get("results")?.as_array()?;
    let blob: String = results
        .iter()
        .filter_map(|r: &Value| r.get("matches").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<&str>>()
        .join("\n");
    Some(
        GROUND_TRUTH
            .iter()
            .enumerate()
            .filter_map(|(i, s): (usize, &PlantedSecret)| blob.contains(&s.token()).then_some(i))
            .collect(),
    )
}

fn extract_apk(apk_bytes: &[u8], dst: &Path) -> Result<()> {
    extract_apk_with_limits(
        apk_bytes,
        dst,
        MAX_ZIP_ENTRIES,
        MAX_ZIP_ENTRY_BYTES,
        MAX_ZIP_TOTAL_BYTES,
    )
}

fn extract_apk_with_limits(
    apk_bytes: &[u8],
    dst: &Path,
    max_entries: usize,
    max_entry_bytes: u64,
    max_total_bytes: u64,
) -> Result<()> {
    let reader: std::io::Cursor<&[u8]> = std::io::Cursor::new(apk_bytes);
    let mut z: zip::ZipArchive<std::io::Cursor<&[u8]>> =
        zip::ZipArchive::new(reader).wrap_err("opening APK as zip")?;
    if z.len() > max_entries {
        bail!("APK contains more than {max_entries} zip entries");
    }
    let mut total_bytes: u64 = 0;
    for i in 0..z.len() {
        let entry: zip::read::ZipFile<'_> = z.by_index(i).wrap_err("zip entry")?;
        let Some(rel): Option<PathBuf> = entry.enclosed_name() else {
            continue;
        };
        let entry_size: u64 = entry.size();
        if entry_size > max_entry_bytes {
            bail!(
                "APK entry {} exceeds {max_entry_bytes} bytes",
                rel.display()
            );
        }
        let out: PathBuf = dst.join(&rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out).wrap_err("mkdir")?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).wrap_err("mkdir parent")?;
        }
        let mut bytes: Vec<u8> = Vec::new();
        let mut limited: std::io::Take<zip::read::ZipFile<'_>> =
            entry.take(max_entry_bytes.saturating_add(1));
        let read_len: usize = limited.read_to_end(&mut bytes).wrap_err("read entry")?;
        let read_len_u64: u64 = u64::try_from(read_len).unwrap_or(u64::MAX);
        if read_len_u64 > max_entry_bytes {
            bail!(
                "APK entry {} grew past {max_entry_bytes} bytes",
                rel.display()
            );
        }
        let Some(next_total): Option<u64> = total_bytes.checked_add(read_len_u64) else {
            bail!("APK extracted byte count overflowed");
        };
        if next_total > max_total_bytes {
            bail!("APK extracted content exceeds {max_total_bytes} bytes");
        }
        total_bytes = next_total;
        std::fs::write(&out, &bytes).wrap_err("write entry")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use disrobe_core::recon::{ReconCategory, ReconError};

    use super::*;
    use crate::published::{
        PublishedBar, assert_published_membership_is_exact,
        assert_published_membership_is_recovered, checked_workspace_root, published_bar,
    };

    const PUBLISHED_HEADING: &str = "Secret recall on the committed planted APK";
    const PUBLISHED_DISROBE_BAR: &str = "disrobe frisk";
    const PUBLISHED_APKLEAKS_BAR: &str = "apkleaks 2.6.3";
    const APKLEAKS_MEASURED_VERSION: &str = "2.6.3";
    fn planted_labels(hits: &[usize]) -> BTreeSet<String> {
        hits.iter()
            .filter_map(|index: &usize| GROUND_TRUTH.get(*index))
            .map(|secret: &PlantedSecret| secret.label.to_owned())
            .collect()
    }

    #[test]
    fn published_planted_apk_secret_bars_are_pinned_by_membership()
    -> core::result::Result<(), String> {
        assert!(
            PUBLISHED_APKLEAKS_BAR.ends_with(APKLEAKS_MEASURED_VERSION),
            "the published apkleaks bar label must name the version this row grades, so the label \
             and the version this check enforces cannot drift apart"
        );
        let root: PathBuf = checked_workspace_root();
        let apk: PathBuf = root
            .join("corpus")
            .join("recon")
            .join("apk")
            .join("planted-secrets.apk");
        assert!(
            apk.is_file(),
            "{} is committed and both tools read it; without it neither side of this published row \
             is measured against anything",
            apk.display()
        );
        let read: Result<Vec<u8>> = read_bounded_file(&apk, MAX_FIXTURE_BYTES);
        assert!(
            read.is_ok(),
            "{} must be readable: {:?}",
            apk.display(),
            read.as_ref().err()
        );
        let apk_bytes: Vec<u8> = read.unwrap_or_default();

        let tree: PathBuf =
            std::env::temp_dir().join(format!("disrobe_h2h_pinned_frisk_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tree);
        let extracted: Result<()> = extract_apk(&apk_bytes, &tree);
        assert!(
            extracted.is_ok(),
            "the planted APK must extract before frisk scans it: {:?}",
            extracted.as_ref().err()
        );
        let scanned: core::result::Result<ReconReport, ReconError> =
            report_tree(&tree, &ReconConfig::default());
        assert!(
            scanned.is_ok(),
            "frisk must scan the extracted planted APK tree: {:?}",
            scanned.as_ref().err()
        );
        let disrobe_hits: Vec<usize> = scanned.map_or_else(
            |_| Vec::new(),
            |report: ReconReport| recall_indices_disrobe(&report),
        );
        let _ = std::fs::remove_dir_all(&tree);
        let disrobe_found: BTreeSet<String> = planted_labels(&disrobe_hits);

        let artifacts: ScratchDir =
            ScratchDir::create("disrobe_h2h_live_apkleaks").map_err(|error| error.to_string())?;
        let run_dir: PathBuf = artifacts.path().join("run");
        std::fs::create_dir(&run_dir).map_err(|error| error.to_string())?;
        let (version, live_hits, raw_json_sha256): (String, Vec<usize>, String) =
            match run_apkleaks(&root, &apk, &run_dir) {
                ApkleaksResult::Ok {
                    version,
                    hits,
                    via,
                    raw_json_sha256,
                    ..
                } if via == "cli" => (version, hits, raw_json_sha256),
                ApkleaksResult::Ok { via, .. } => {
                    return Err(format!("apkleaks used an ungraded execution route: {via}"));
                }
                ApkleaksResult::Skipped(reason) => {
                    return Err(format!("apkleaks was unavailable: {reason}"));
                }
                ApkleaksResult::Error { version, reason } => {
                    return Err(format!("apkleaks `{version}` failed: {reason}"));
                }
            };
        if !version.contains(APKLEAKS_MEASURED_VERSION) {
            return Err(format!(
                "apkleaks reports `{version}`, not the {APKLEAKS_MEASURED_VERSION} series"
            ));
        }
        if raw_json_sha256.len() != 64 {
            return Err("the retained live apkleaks JSON has no SHA-256".to_owned());
        }
        let apkleaks_found: BTreeSet<String> = planted_labels(&live_hits);

        for (index, secret) in GROUND_TRUTH.iter().enumerate() {
            eprintln!(
                "planted secret {index} `{label}` = {token} | disrobe={disrobe} apkleaks={apkleaks}",
                label = secret.label,
                token = secret.token(),
                disrobe = disrobe_found.contains(secret.label),
                apkleaks = apkleaks_found.contains(secret.label),
            );
        }

        let disrobe_bar: PublishedBar = published_bar(PUBLISHED_HEADING, PUBLISHED_DISROBE_BAR);
        eprintln!(
            "published `{label}` {num}/{den} = {value}; measured {measured}/{total} {found:?}",
            label = disrobe_bar.label,
            num = disrobe_bar.num,
            den = disrobe_bar.den,
            value = disrobe_bar.value,
            measured = disrobe_found.len(),
            total = GROUND_TRUTH.len(),
            found = disrobe_found,
        );
        assert_published_membership_is_recovered(&disrobe_bar, &disrobe_found, GROUND_TRUTH.len());

        let apkleaks_bar: PublishedBar = published_bar(PUBLISHED_HEADING, PUBLISHED_APKLEAKS_BAR);
        eprintln!(
            "published `{label}` {num}/{den} = {value}; live {measured}/{total} {found:?}",
            label = apkleaks_bar.label,
            num = apkleaks_bar.num,
            den = apkleaks_bar.den,
            value = apkleaks_bar.value,
            measured = apkleaks_found.len(),
            total = GROUND_TRUTH.len(),
            found = apkleaks_found,
        );
        assert_published_membership_is_exact(&apkleaks_bar, &apkleaks_found, GROUND_TRUTH.len());
        Ok(())
    }

    #[test]
    fn apkleaks_json_recall_matches_planted_tokens() -> core::result::Result<(), String> {
        let akid: String = GROUND_TRUTH[0].token();
        let firebase: String = GROUND_TRUTH[6].token();
        let raw: String = format!(
            "{{\"package\":\"p\",\"results\":[\
             {{\"name\":\"Amazon_AWS_Access_Key_ID\",\"matches\":[\"{akid}\"]}},\
             {{\"name\":\"Firebase\",\"matches\":[\"{firebase}\"]}}]}}"
        );
        let Some(hits): Option<Vec<usize>> = recall_indices_apkleaks(&raw) else {
            return Err("expected apkleaks recall indices".to_owned());
        };
        assert!(hits.contains(&0), "AWS AKID is index 0");
        assert!(hits.contains(&6), "Firebase is index 6");
        assert!(
            !hits.contains(&1),
            "AWS secret was not in the apkleaks output"
        );
        Ok(())
    }

    #[test]
    fn unrelated_value_with_the_same_rule_is_not_a_planted_hit() {
        let report: ReconReport = ReconReport {
            schema: "test",
            root: None,
            files_scanned: 1,
            bytes_scanned: 7,
            non_utf8_files: 0,
            total: 1,
            findings: vec![ReconFinding {
                category: ReconCategory::Secret,
                rule_id: "DR-SEC-AWS-AKID".to_owned(),
                value: "AKIAUNRELATEDVALUE".to_owned(),
                path: Some("classes.smali".to_owned()),
                line: 1,
                column: 1,
                offset: 0,
                severity: "error".to_owned(),
            }],
        };
        assert!(recall_indices_disrobe(&report).is_empty());
    }

    #[test]
    fn jadx_path_prefix_preserves_caller_search_entries() -> core::result::Result<(), String> {
        let inherited_entries: [PathBuf; 2] =
            [PathBuf::from("caller-bin"), PathBuf::from("system-bin")];
        let inherited: std::ffi::OsString =
            std::env::join_paths(&inherited_entries).map_err(|error| error.to_string())?;
        let prefixed: String = prefixed_search_path(Path::new("selected-jadx"), &inherited)?;
        let actual: Vec<PathBuf> = std::env::split_paths(OsStr::new(&prefixed)).collect();
        assert_eq!(
            actual,
            [
                PathBuf::from("selected-jadx"),
                inherited_entries[0].clone(),
                inherited_entries[1].clone()
            ]
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn windows_jadx_prefix_preserves_an_unquoted_command_token() -> Result<(), String> {
        let inherited: &OsStr = OsStr::new(r"C:\System Paths;D:\bin");
        assert_eq!(
            prefixed_search_path(Path::new(r"C:\tools\jadx\bin"), inherited)?,
            r"C:/tools/jadx/bin/;C:\System Paths;D:\bin"
        );
        assert!(jadx_search_prefix(Path::new(r"C:\Program Files\jadx\bin")).is_err());
        assert!(jadx_search_prefix(Path::new(r"C:\%tools%\jadx\bin")).is_err());
        Ok(())
    }

    #[test]
    fn apkleaks_miss_names_come_from_live_hit_indices() {
        let disrobe_hits: Vec<usize> = (0..GROUND_TRUTH.len()).collect();
        let apkleaks_hits: Vec<usize> = vec![0, 6];
        let tools: Vec<Value> = vec![
            tool_json("disrobe", "v", &disrobe_hits, "ok", None),
            tool_json("apkleaks", "v", &apkleaks_hits, "ok", None),
        ];
        let note: String = honest_note(&tools, &apkleaks_hits);
        assert!(note.contains(GROUND_TRUTH[1].label));
        assert!(!note.contains(GROUND_TRUTH[0].label));
        assert!(!note.contains(GROUND_TRUTH[6].label));
    }

    #[test]
    fn serialized_frisk_report_is_retained_with_its_hash() -> core::result::Result<(), String> {
        let artifacts: ScratchDir =
            ScratchDir::create("disrobe_h2h_frisk_report").map_err(|error| error.to_string())?;
        let report: ReconReport = ReconReport {
            schema: "test",
            root: None,
            files_scanned: 0,
            bytes_scanned: 0,
            non_utf8_files: 0,
            total: 0,
            findings: Vec::new(),
        };
        let digest: String = retain_recon_report(artifacts.path(), &report)?;
        let raw: Vec<u8> =
            std::fs::read(artifacts.path().join("disrobe").join("recon-report.json"))
                .map_err(|error| error.to_string())?;
        assert_eq!(digest, apkleaks_capture::sha256_hex(&raw));
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).map_err(|error| error.to_string())?["total"],
            0
        );
        let original: Vec<u8> = std::fs::read(
            artifacts
                .path()
                .join("disrobe")
                .join("recon-report.raw.json"),
        )
        .map_err(|error| error.to_string())?;
        assert!(
            serde_json::from_slice::<Value>(&original)
                .map_err(|error| error.to_string())?
                .get("root")
                .is_none()
        );
        let relocated: ReconReport = ReconReport {
            root: Some("another-scratch-directory".to_owned()),
            ..report.clone()
        };
        let other: ScratchDir =
            ScratchDir::create("disrobe_h2h_frisk_relocated").map_err(|error| error.to_string())?;
        assert_eq!(digest, retain_recon_report(other.path(), &relocated)?);
        let changed: ReconReport = ReconReport {
            bytes_scanned: 1,
            ..report
        };
        let changed_dir: ScratchDir =
            ScratchDir::create("disrobe_h2h_frisk_changed").map_err(|error| error.to_string())?;
        assert_ne!(digest, retain_recon_report(changed_dir.path(), &changed)?);
        Ok(())
    }

    #[test]
    fn apkleaks_measurement_preserves_raw_provenance_across_platforms() -> Result<()> {
        let root: PathBuf = checked_workspace_root();
        let capture: String =
            read_bounded_string(&apkleaks_capture::capture_path(&root), MAX_TEXT_BYTES)?;
        let lf: String = capture.replace("\r\n", "\n");
        let crlf: String = lf.replace('\n', "\r\n");
        assert_eq!(
            apkleaks_capture::sha256_hex(lf.as_bytes()),
            "dd530528036c7dd632b7e4886293cf3dbf2c7c52528b5ce02c1be30dcd24ddee"
        );
        let mut measurements: Vec<Value> = Vec::new();
        let mut provenance_hashes: Vec<Value> = Vec::new();
        for (raw, launcher, launcher_hash) in [
            (lf, "/opt/jadx/bin/jadx", "11".repeat(32)),
            (crlf, "C:/tools/jadx/bin/jadx.bat", "22".repeat(32)),
        ] {
            let artifacts: ScratchDir = ScratchDir::create("disrobe_h2h_apkleaks_platform")?;
            let result: ApkleaksResult =
                retained_apkleaks_test_result(artifacts.path(), &raw, launcher, &launcher_hash)?;
            let (_, measurement): (Vec<usize>, Value) =
                retain_apkleaks_measurement(&result, artifacts.path())?;
            let artifact_dir: PathBuf = artifacts.path().join("apkleaks");
            let original: Vec<u8> = std::fs::read(artifact_dir.join("apkleaks.json"))?;
            assert_eq!(original, raw.as_bytes());
            let normalized: Vec<u8> = std::fs::read(artifact_dir.join("apkleaks.lf.json"))?;
            assert_eq!(
                serde_json::from_slice::<Value>(&original)?,
                serde_json::from_slice::<Value>(&normalized)?
            );
            assert_eq!(
                measurement["lf_json_sha256"],
                apkleaks_capture::sha256_hex(&normalized)
            );
            assert_eq!(
                measurement["lf_json_artifact"],
                "frisk-apkleaks/apkleaks/apkleaks.lf.json"
            );
            assert_eq!(
                measurement["raw_json_artifact"],
                "frisk-apkleaks/apkleaks/apkleaks.json"
            );
            assert_eq!(
                measurement["report_provenance_artifact"],
                "frisk-apkleaks/apkleaks/report-provenance.json"
            );
            let provenance: Value = serde_json::from_slice(&std::fs::read(
                artifact_dir.join("report-provenance.json"),
            )?)?;
            assert_eq!(provenance["raw_json_artifact"], "apkleaks.json");
            assert_eq!(
                provenance["raw_json_sha256"],
                apkleaks_capture::sha256_hex(&original)
            );
            assert_eq!(provenance["raw_json_bytes"], original.len());
            assert_eq!(provenance["lf_json_artifact"], "apkleaks.lf.json");
            assert_eq!(provenance["lf_json_sha256"], measurement["lf_json_sha256"]);
            assert_eq!(provenance["lf_json_bytes"], normalized.len());
            assert_eq!(provenance["jadx_executable"], launcher);
            assert_eq!(provenance["jadx_executable_sha256"], launcher_hash);
            assert_eq!(
                provenance["jadx_provenance_artifact"],
                "jadx/provenance.json"
            );
            provenance_hashes.push(provenance["raw_json_sha256"].clone());
            measurements.push(measurement);
        }
        assert_ne!(provenance_hashes[0], provenance_hashes[1]);
        assert_eq!(measurements[0], measurements[1]);
        Ok(())
    }

    #[test]
    fn apkleaks_measurement_detects_changed_json_values() -> Result<()> {
        let root: PathBuf = checked_workspace_root();
        let capture: String =
            read_bounded_string(&apkleaks_capture::capture_path(&root), MAX_TEXT_BYTES)?;
        let capture: String =
            serde_json::to_string_pretty(&serde_json::from_str::<Value>(&capture)?)?;
        let mut changed_package: Value = serde_json::from_str(&capture)?;
        changed_package["package"] = Value::String("changed.package".to_owned());
        let missing_secret: String = capture.replace(&GROUND_TRUTH[0].token(), "removed-token");
        assert_ne!(capture, missing_secret);
        let mut measurements: Vec<Value> = Vec::new();
        for raw in [
            capture,
            serde_json::to_string_pretty(&changed_package)?,
            missing_secret,
        ] {
            let artifacts: ScratchDir = ScratchDir::create("disrobe_h2h_apkleaks_changed")?;
            let result: ApkleaksResult =
                retained_apkleaks_test_result(artifacts.path(), &raw, "jadx", &"11".repeat(32))?;
            let (_, measurement): (Vec<usize>, Value) =
                retain_apkleaks_measurement(&result, artifacts.path())?;
            measurements.push(measurement);
        }
        assert_eq!(measurements[0]["found"], 5);
        assert_eq!(measurements[1]["found"], 5);
        assert_eq!(measurements[2]["found"], 4);
        for changed in &measurements[1..] {
            assert_ne!(measurements[0]["lf_json_sha256"], changed["lf_json_sha256"]);
            assert_ne!(measurements[0], *changed);
        }
        Ok(())
    }

    #[test]
    fn apkleaks_measurement_rejects_replaced_raw_report() -> Result<()> {
        let artifacts: ScratchDir = ScratchDir::create("disrobe_h2h_apkleaks_replaced")?;
        let result: ApkleaksResult = retained_apkleaks_test_result(
            artifacts.path(),
            "{\"results\":[]}",
            "jadx",
            &"11".repeat(32),
        )?;
        let artifact_dir: PathBuf = artifacts.path().join("apkleaks");
        let replacement: &[u8] = b"{\"results\":[],\"package\":\"changed\"}";
        std::fs::write(artifact_dir.join("apkleaks.json"), replacement)?;
        let Err(error) = retain_apkleaks_measurement(&result, artifacts.path()) else {
            bail!("replaced report was published with the graded checksum");
        };
        assert!(error.to_string().contains("differs from the graded report"));
        assert_eq!(
            std::fs::read(artifact_dir.join("apkleaks.json"))?,
            replacement
        );
        assert!(!artifact_dir.join("apkleaks.lf.json").exists());
        assert!(!artifact_dir.join("report-provenance.json").exists());
        Ok(())
    }

    fn retained_apkleaks_test_result(
        run_dir: &Path,
        raw: &str,
        launcher: &str,
        launcher_hash: &str,
    ) -> Result<ApkleaksResult> {
        let artifact_dir: PathBuf = run_dir.join("apkleaks");
        std::fs::create_dir(&artifact_dir)?;
        std::fs::write(artifact_dir.join("apkleaks.json"), raw)?;
        Ok(ApkleaksResult::Ok {
            version: "APKLeaks v2.6.3".to_owned(),
            hits: recall_indices_apkleaks(raw).ok_or_else(|| eyre::eyre!("invalid test report"))?,
            via: "cli".to_owned(),
            raw_json_sha256: apkleaks_capture::sha256_hex(raw.as_bytes()),
            jadx_version: "1.5.5".to_owned(),
            jadx_executable: PathBuf::from(launcher),
            jadx_executable_sha256: launcher_hash.to_owned(),
        })
    }

    #[test]
    fn ground_truth_has_eight_distinct_secrets() {
        assert_eq!(GROUND_TRUTH.len(), 8);
        let mut tokens: Vec<String> = GROUND_TRUTH.iter().map(PlantedSecret::token).collect();
        tokens.sort_unstable();
        tokens.dedup();
        assert_eq!(tokens.len(), 8, "ground-truth tokens must be distinct");
    }

    #[test]
    fn apkleaks_cli_zero_hits_remains_a_live_scored_result() -> core::result::Result<(), String> {
        let result: ApkleaksResult = select_apkleaks_result(
            "v".to_owned(),
            ApkleaksCliResult::Ok {
                hits: Vec::new(),
                raw_json_sha256: "00".repeat(32),
                jadx_version: "1.5.5".to_owned(),
                jadx_executable: PathBuf::from("jadx"),
                jadx_executable_sha256: "11".repeat(32),
            },
        );
        match result {
            ApkleaksResult::Ok {
                hits,
                via,
                jadx_executable,
                jadx_executable_sha256,
                ..
            } => {
                assert!(
                    hits.is_empty(),
                    "zero-hit CLI result is the measured result"
                );
                assert_eq!(via, "cli");
                assert_eq!(jadx_executable, PathBuf::from("jadx"));
                assert_eq!(jadx_executable_sha256, "11".repeat(32));
            }
            ApkleaksResult::Skipped(_) | ApkleaksResult::Error { .. } => {
                return Err("expected CLI result".to_owned());
            }
        }
        Ok(())
    }

    #[test]
    fn apkleaks_cli_failure_cannot_be_replaced_by_offline_rules() -> core::result::Result<(), String>
    {
        let result: ApkleaksResult = select_apkleaks_result(
            "v".to_owned(),
            ApkleaksCliResult::Failed("cli failed".to_owned()),
        );
        match result {
            ApkleaksResult::Error { reason, .. } => {
                assert_eq!(reason, "cli failed");
            }
            ApkleaksResult::Ok { .. } | ApkleaksResult::Skipped(_) => {
                return Err("a failed live run must remain failed".to_owned());
            }
        }
        Ok(())
    }

    #[test]
    fn mandatory_apkleaks_rejects_fallback_and_unusable_results() {
        let fallback: ApkleaksResult = ApkleaksResult::Ok {
            version: "v2.6.3".to_owned(),
            hits: vec![1],
            via: "pinned-rules".to_owned(),
            raw_json_sha256: "00".repeat(32),
            jadx_version: "1.5.5".to_owned(),
            jadx_executable: PathBuf::from("jadx"),
            jadx_executable_sha256: "11".repeat(32),
        };
        let skipped: ApkleaksResult = ApkleaksResult::Skipped("not found".to_owned());
        let failed: ApkleaksResult = ApkleaksResult::Error {
            version: "v2.6.3".to_owned(),
            reason: "broken".to_owned(),
        };
        assert!(require_live_apkleaks(&fallback).is_err());
        assert!(require_live_apkleaks(&skipped).is_err());
        assert!(require_live_apkleaks(&failed).is_err());
        let live: ApkleaksResult = ApkleaksResult::Ok {
            version: "v2.6.3".to_owned(),
            hits: vec![1],
            via: "cli".to_owned(),
            raw_json_sha256: "00".repeat(32),
            jadx_version: "1.5.5".to_owned(),
            jadx_executable: PathBuf::from("jadx"),
            jadx_executable_sha256: "11".repeat(32),
        };
        assert!(require_live_apkleaks(&live).is_ok());
    }

    #[test]
    fn extract_apk_rejects_entry_size_cap() -> core::result::Result<(), String> {
        let apk: Vec<u8> = apk_zip(&[("classes.dex", b"abcdef".as_slice())])?;
        let root: PathBuf = temp_dir("entry-cap");
        let _ = std::fs::remove_dir_all(&root);
        let result: Result<()> = extract_apk_with_limits(&apk, &root, 8, 5, 64);
        let _ = std::fs::remove_dir_all(&root);
        assert!(
            result.is_err(),
            "six bytes must exceed a five-byte entry cap"
        );
        Ok(())
    }

    fn temp_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("disrobe_h2h_frisk_{}_{}", std::process::id(), name))
    }

    fn apk_zip(entries: &[(&str, &[u8])]) -> core::result::Result<Vec<u8>, String> {
        use std::io::Write as _;

        let cursor: std::io::Cursor<Vec<u8>> = std::io::Cursor::new(Vec::new());
        let mut zip: zip::ZipWriter<std::io::Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let options: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, payload) in entries {
            zip.start_file(*name, options).map_err(|e| e.to_string())?;
            zip.write_all(payload).map_err(|e| e.to_string())?;
        }
        let cursor: std::io::Cursor<Vec<u8>> = zip.finish().map_err(|e| e.to_string())?;
        Ok(cursor.into_inner())
    }
}
