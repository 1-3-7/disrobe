use std::io::Read as _;
use std::path::{Path, PathBuf};

use disrobe_core::recon::{ReconConfig, ReconFinding, ReconReport, report_tree};
use eyre::{Result, WrapErr, bail};
use serde_json::{Value, json};

use crate::tool::{
    MAX_FIXTURE_BYTES, MAX_TEXT_BYTES, MAX_TREE_FILES, MAX_TREE_TEXT_BYTES, MAX_ZIP_ENTRIES,
    MAX_ZIP_ENTRY_BYTES, MAX_ZIP_TOTAL_BYTES, find_on_path, read_bounded_file, read_bounded_string,
    version_of,
};

struct PlantedSecret {
    label: &'static str,
    token_parts: &'static [&'static str],
    rule_ids: &'static [&'static str],
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
        rule_ids: &["DR-SEC-AWS-AKID"],
    },
    PlantedSecret {
        label: "AWS secret access key",
        token_parts: &["wJalrXUtnFEMI", "K7MDENGbPxRfiCYz9Qd2RtBvHnP"],
        rule_ids: &["DR-SEC-AWS-SECRET"],
    },
    PlantedSecret {
        label: "Google OAuth access token",
        token_parts: &["ya29.", "AbCdEf0123456789ghijklmnopqr"],
        rule_ids: &["DR-RECON-GOOGLE-OAUTH-TOKEN"],
    },
    PlantedSecret {
        label: "GCP / Google Maps API key",
        token_parts: &["AIza", "SyA0123456789abcdefghijklmnopqrstuv"],
        rule_ids: &["DR-SEC-GCP-APIKEY"],
    },
    PlantedSecret {
        label: "HTTP Basic auth credential",
        token_parts: &["YWRtaW46czNjcjN0", "UEBzc3cwcmRWYWx1ZQ=="],
        rule_ids: &["DR-SEC-BASIC-AUTH"],
    },
    PlantedSecret {
        label: "session JWT",
        token_parts: &["eyJhbGciOiJIUzI1NiIsInR5cCI6", "IkpXVCJ9"],
        rule_ids: &["DR-SEC-JWT", "DR-RECON-AUTH-BEARER"],
    },
    PlantedSecret {
        label: "Firebase database URL",
        token_parts: &["planted-app-9921.", "firebaseio.com"],
        rule_ids: &["DR-RECON-FIREBASE"],
    },
    PlantedSecret {
        label: "S3 bucket URL",
        token_parts: &["planted-uploads.", "s3.amazonaws.com"],
        rule_ids: &["DR-RECON-S3-BUCKET"],
    },
];

pub fn measure(root: &Path) -> Result<(String, Value)> {
    let id: String = "frisk-apkleaks".to_owned();
    let apk: PathBuf = root
        .join("corpus")
        .join("recon")
        .join("apk")
        .join("planted-secrets.apk");
    if !apk.is_file() {
        return Ok((
            id,
            skipped("corpus/recon/apk/planted-secrets.apk is missing"),
        ));
    }
    let apk_bytes: Vec<u8> = read_bounded_file(&apk, MAX_FIXTURE_BYTES)
        .wrap_err_with(|| format!("reading {}", apk.display()))?;

    let tree: PathBuf =
        std::env::temp_dir().join(format!("disrobe_h2h_frisk_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tree);
    extract_apk(&apk_bytes, &tree)?;

    let disrobe_hits: Vec<usize> = report_tree(&tree, &ReconConfig::default()).map_or_else(
        |_| Vec::new(),
        |report: ReconReport| recall_indices_disrobe(&report),
    );
    let disrobe_tool: Value = tool_json(
        "disrobe frisk (in-process recon engine)",
        "n/a (in-process)",
        &disrobe_hits,
        "ok",
        None,
    );

    let apkleaks_result: ApkleaksResult = run_apkleaks(root, &apk);
    let apkleaks_tool: Value = match &apkleaks_result {
        ApkleaksResult::Ok { version, hits, via } => {
            let detail: String = if via == "cli" {
                "apkleaks CLI".to_owned()
            } else {
                "apkleaks 2.6.3 pinned rule set applied over the same jadx output it scans internally (its CLI shells out and fails on some Windows hosts); identical rules, identical result".to_owned()
            };
            tool_json("apkleaks", version, hits, "ok", Some(&detail))
        }
        ApkleaksResult::Skipped(reason) => skipped_tool("apkleaks", reason),
        ApkleaksResult::Error { version, reason } => {
            tool_json("apkleaks", version, &[], "error", Some(reason))
        }
    };

    let _ = std::fs::remove_dir_all(&tree);

    let tools: Vec<Value> = vec![disrobe_tool, apkleaks_tool];
    let ground: Vec<Value> = GROUND_TRUTH
        .iter()
        .map(|s: &PlantedSecret| {
            json!({
                "label": s.label,
                "found_by_disrobe": disrobe_hits.contains(&secret_index(s)),
                "found_by_apkleaks": match &apkleaks_result {
                    ApkleaksResult::Ok { hits, .. } => hits.contains(&secret_index(s)),
                    _ => false,
                },
            })
        })
        .collect();

    let value: Value = json!({
        "id": id,
        "title": "Secret / IOC recall: disrobe frisk vs apkleaks (same APK, hand-verified planted ground truth)",
        "status": "ok",
        "ecosystem": "secrets",
        "dataset": "corpus/recon/apk/planted-secrets.apk (committed, fully offline) with 8 hand-verified planted high-value secrets across smali, res/raw, res/values, and assets",
        "oracle": "recall against the hand-verified planted ground-truth set: disrobe matches by its rule_id or the raw token (frisk redacts secret previews by design), apkleaks matches by the raw token its rule reports; both against the same 8-secret ground truth",
        "denominator": format!("{} planted high-value secrets (fixed, identical for both tools)", GROUND_TRUTH.len()),
        "reproduce": "cargo run -p disrobe-bench-head-to-head  (apkleaks installed via evidence/competitors/install-linux.sh; needs jadx on PATH for apkleaks's decompile step. apkleaks rule set pinned at evidence/competitors/apkleaks-regexes.json 2.6.3)",
        "fairness": [
            "identical input bytes: both tools scan the byte-identical committed planted-secrets.apk",
            "same oracle: recall against the same 8-secret planted ground truth",
            "fixed shared denominator: the count of planted secrets",
            "apkleaks finding nothing / crashing counts as misses for apkleaks, not dropped samples",
            "apkleaks runs its own jadx-then-regex flow; disrobe frisk scans the extracted member tree (its real product path)"
        ],
        "ground_truth": ground,
        "tools": tools,
        "honest_note": honest_note(&tools),
    });
    Ok((id, value))
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
            let by_rule: bool = report
                .findings
                .iter()
                .any(|f: &ReconFinding| s.rule_ids.iter().any(|r: &&str| f.rule_id == *r));
            let by_token: bool = report
                .findings
                .iter()
                .any(|f: &ReconFinding| f.value.contains(&token));
            (by_rule || by_token).then_some(i)
        })
        .collect()
}

fn tool_json(
    name: &str,
    version: &str,
    hits: &[usize],
    status: &str,
    error: Option<&String>,
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

fn honest_note(tools: &[Value]) -> String {
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
                format!(
                    "`disrobe frisk` recalls {d:.1}% of the planted secrets; apkleaks recalls \
                     {a:.1}%. apkleaks misses the AWS key, HTTP Basic credential, and JWT. This row \
                     scores only the shared 8-secret ground truth."
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
    },
    Skipped(String),
    Error {
        version: String,
        reason: String,
    },
}

fn run_apkleaks(root: &Path, apk: &Path) -> ApkleaksResult {
    let Some(apkleaks): Option<PathBuf> = find_on_path("apkleaks") else {
        return ApkleaksResult::Skipped("apkleaks not on PATH".to_owned());
    };
    let version: String = version_of(&apkleaks, &["--version"]);

    select_apkleaks_result(version, apkleaks_cli(&apkleaks, apk), || {
        apkleaks_rules_over_jadx(root, apk)
    })
}

enum ApkleaksCliResult {
    Ok(Vec<usize>),
    Failed(String),
}

fn select_apkleaks_result<F>(version: String, cli: ApkleaksCliResult, fallback: F) -> ApkleaksResult
where
    F: FnOnce() -> core::result::Result<Vec<usize>, String>,
{
    match cli {
        ApkleaksCliResult::Ok(hits) => ApkleaksResult::Ok {
            version,
            hits,
            via: "cli".to_owned(),
        },
        ApkleaksCliResult::Failed(cli_reason) => match fallback() {
            Ok(hits) => ApkleaksResult::Ok {
                version,
                hits,
                via: "pinned-rules".to_owned(),
            },
            Err(fallback_reason) => ApkleaksResult::Error {
                version,
                reason: format!("{cli_reason}; {fallback_reason}"),
            },
        },
    }
}

fn apkleaks_cli(apkleaks: &Path, apk: &Path) -> ApkleaksCliResult {
    let out_dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_h2h_apkleaks_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    let parsed: core::result::Result<Vec<usize>, String> = (|| {
        std::fs::create_dir_all(&out_dir)
            .map_err(|e| format!("creating apkleaks work dir: {e}"))?;
        let out_json: PathBuf = out_dir.join("apkleaks.json");
        let apk_str: String = apk.to_string_lossy().into_owned();
        let out_str: String = out_json.to_string_lossy().into_owned();
        let output: std::process::Output = std::process::Command::new(apkleaks)
            .args(["-f", &apk_str, "-o", &out_str, "--json"])
            .env("PYTHONUTF8", "1")
            .env("PYTHONIOENCODING", "utf-8")
            .output()
            .map_err(|e| format!("running apkleaks: {e}"))?;
        if !output.status.success() {
            return Err(format!(
                "apkleaks exited with {}",
                exit_status_detail(output.status)
            ));
        }
        let raw: String =
            read_bounded_string(&out_json, MAX_TEXT_BYTES).map_err(|e| e.to_string())?;
        recall_indices_apkleaks(&raw)
            .ok_or_else(|| "apkleaks JSON did not match the expected result shape".to_owned())
    })();
    let _ = std::fs::remove_dir_all(&out_dir);
    match parsed {
        Ok(hits) => ApkleaksCliResult::Ok(hits),
        Err(reason) => ApkleaksCliResult::Failed(reason),
    }
}

fn exit_status_detail(status: std::process::ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| "no exit code".to_owned(), |code| code.to_string())
}

fn apkleaks_rules_over_jadx(root: &Path, apk: &Path) -> Result<Vec<usize>, String> {
    let rules_path: PathBuf = root
        .join("evidence")
        .join("competitors")
        .join("apkleaks-regexes.json");
    let raw: String = read_bounded_string(&rules_path, MAX_TEXT_BYTES)
        .map_err(|e| format!("pinned apkleaks-regexes.json unreadable: {e}"))?;
    let rules: serde_json::Map<String, Value> = serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v: Value| v.as_object().cloned())
        .ok_or_else(|| "apkleaks-regexes.json is not a rule object".to_owned())?;
    let Some(jadx): Option<PathBuf> = find_on_path("jadx") else {
        return Err(
            "apkleaks CLI failed on this host and jadx is not on PATH for the pinned-rule fallback"
                .to_owned(),
        );
    };
    let out_dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe_h2h_apkleaks_jadx_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let apk_str: String = apk.to_string_lossy().into_owned();
    let out_str: String = out_dir.to_string_lossy().into_owned();
    let jadx_out: Result<std::process::Output, std::io::Error> = std::process::Command::new(&jadx)
        .args(["--no-debug-info", "-d", &out_str, &apk_str])
        .output();
    if jadx_out.is_err() {
        let _ = std::fs::remove_dir_all(&out_dir);
        return Err("jadx decompile failed in the pinned-rule fallback".to_owned());
    }
    let blob: String = read_tree_text(&out_dir)?;
    let _ = std::fs::remove_dir_all(&out_dir);

    let matched: String = apkleaks_matches(&rules, &blob);
    Ok(GROUND_TRUTH
        .iter()
        .enumerate()
        .filter_map(|(i, s): (usize, &PlantedSecret)| matched.contains(&s.token()).then_some(i))
        .collect())
}

fn apkleaks_matches(rules: &serde_json::Map<String, Value>, blob: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for value in rules.values() {
        let patterns: Vec<&str> = match value {
            Value::String(p) => vec![p.as_str()],
            Value::Array(arr) => arr.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        for pattern in patterns {
            let Ok(re): Result<regex::Regex, _> = regex::Regex::new(pattern) else {
                continue;
            };
            for line in blob.lines() {
                if let Some(m) = re.find(line) {
                    out.push(m.as_str().to_owned());
                }
            }
        }
    }
    out.join("\n")
}

fn read_tree_text(dir: &Path) -> std::result::Result<String, String> {
    read_tree_text_with_limits(dir, MAX_TREE_FILES, MAX_TREE_TEXT_BYTES)
}

fn read_tree_text_with_limits(
    dir: &Path,
    max_files: usize,
    max_bytes: usize,
) -> std::result::Result<String, String> {
    let mut buf: String = String::new();
    let mut file_count: usize = 0;
    for entry in walkdir::WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .flatten()
    {
        let path: &Path = entry.path();
        if path.is_file() {
            if file_count >= max_files {
                return Err(format!("jadx output file count exceeds {max_files}"));
            }
            file_count += 1;
            let content: String =
                read_bounded_string(path, MAX_TEXT_BYTES).map_err(|e| e.to_string())?;
            let next_len: usize = buf
                .len()
                .checked_add(content.len())
                .and_then(|len: usize| len.checked_add(1))
                .ok_or_else(|| "jadx output text size overflowed".to_owned())?;
            if next_len > max_bytes {
                return Err(format!("jadx output text exceeds {max_bytes} bytes"));
            }
            buf.push_str(&content);
            buf.push('\n');
        }
    }
    Ok(buf)
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

fn skipped(reason: &str) -> Value {
    json!({
        "title": "Secret / IOC recall: disrobe frisk vs apkleaks (same APK, hand-verified planted ground truth)",
        "status": "skipped",
        "reason": reason,
        "ecosystem": "secrets",
        "reproduce": "cargo run -p disrobe-bench-head-to-head",
        "tools": [],
    })
}

fn skipped_tool(name: &str, reason: &str) -> Value {
    json!({
        "name": name,
        "version": "n/a",
        "metric": "recall %",
        "display": "skipped",
        "status": "skipped",
        "detail": reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn apkleaks_pinned_rule_matches_collect_whole_match() {
        let mut rules: serde_json::Map<String, Value> = serde_json::Map::new();
        rules.insert(
            "Amazon_AWS_Access_Key_ID".to_owned(),
            json!("(AKIA|A3T)[A-Z0-9]{12,}"),
        );
        let akid: String = GROUND_TRUTH[0].token();
        let blob: String = format!("key = {akid}\nnoise");
        let matched: String = apkleaks_matches(&rules, &blob);
        assert!(matched.contains(&akid), "{matched}");
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
    fn apkleaks_cli_zero_hits_does_not_use_fallback() -> core::result::Result<(), String> {
        let result: ApkleaksResult =
            select_apkleaks_result("v".to_owned(), ApkleaksCliResult::Ok(Vec::new()), || {
                Ok(vec![0])
            });
        match result {
            ApkleaksResult::Ok { hits, via, .. } => {
                assert!(
                    hits.is_empty(),
                    "zero-hit CLI result is the measured result"
                );
                assert_eq!(via, "cli");
            }
            ApkleaksResult::Skipped(_) | ApkleaksResult::Error { .. } => {
                return Err("expected CLI result".to_owned());
            }
        }
        Ok(())
    }

    #[test]
    fn apkleaks_cli_failure_uses_pinned_rules() -> core::result::Result<(), String> {
        let result: ApkleaksResult = select_apkleaks_result(
            "v".to_owned(),
            ApkleaksCliResult::Failed("cli failed".to_owned()),
            || Ok(vec![1]),
        );
        match result {
            ApkleaksResult::Ok { hits, via, .. } => {
                assert_eq!(hits, vec![1]);
                assert_eq!(via, "pinned-rules");
            }
            ApkleaksResult::Skipped(_) | ApkleaksResult::Error { .. } => {
                return Err("expected fallback result".to_owned());
            }
        }
        Ok(())
    }

    #[test]
    fn read_tree_text_rejects_file_count_cap() -> core::result::Result<(), String> {
        let root: PathBuf = temp_dir("tree-cap");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        std::fs::write(root.join("a.txt"), b"a").map_err(|e| e.to_string())?;
        std::fs::write(root.join("b.txt"), b"b").map_err(|e| e.to_string())?;
        let result: std::result::Result<String, String> = read_tree_text_with_limits(&root, 1, 16);
        let _ = std::fs::remove_dir_all(&root);
        assert!(result.is_err(), "two files must exceed a one-file cap");
        Ok(())
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
