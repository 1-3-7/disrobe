use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde_json::Value;

use crate::fileio::read_text_bounded;

const MAX_RECOVERY_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_README_BYTES: u64 = 4 * 1024 * 1024;

struct Binding {
    heading_substr: &'static str,
    bar_label: &'static str,
    format: fn(f64) -> String,
}

fn pct2(value: f64) -> String {
    format!("{value:.2}%")
}

const BINDINGS: &[Binding] = &[
    Binding {
        heading_substr: "Python bytecode",
        bar_label: "full 571-module stdlib (representative)",
        format: pct2,
    },
    Binding {
        heading_substr: "Python bytecode",
        bar_label: "200-module pinned corpus",
        format: pct2,
    },
];

pub(crate) fn run(root: &Path) -> Result<()> {
    let recovery_path: PathBuf = root.join("xtask").join("data").join("recovery.json");
    let readme_path: PathBuf = root.join("README.md");
    let recovery_raw: String = read_text_bounded(&recovery_path, MAX_RECOVERY_JSON_BYTES)
        .wrap_err_with(|| format!("reading {}", recovery_path.display()))?;
    let recovery: Value = serde_json::from_str(&recovery_raw)
        .wrap_err_with(|| format!("parsing {}", recovery_path.display()))?;
    let readme: String = read_text_bounded(&readme_path, MAX_README_BYTES)
        .wrap_err_with(|| format!("reading {}", readme_path.display()))?;

    let mut drift: Vec<String> = Vec::new();
    for binding in BINDINGS {
        let Some(value) = find_bar_value(&recovery, binding.heading_substr, binding.bar_label)
        else {
            bail!(
                "recovery.json has no bar `{}` under a heading containing `{}`",
                binding.bar_label,
                binding.heading_substr
            );
        };
        let formatted: String = (binding.format)(value);
        if !readme.contains(formatted.as_str()) {
            drift.push(format!(
                "README.md no longer contains `{formatted}` (source: recovery.json heading containing `{}`, bar `{}`)",
                binding.heading_substr, binding.bar_label
            ));
        }
    }

    if drift.is_empty() {
        println!(
            "xtask regen: README stat cross-check ok ({} number(s) verified against xtask/data/recovery.json)",
            BINDINGS.len()
        );
        Ok(())
    } else {
        bail!(
            "README.md stat(s) drifted from xtask/data/recovery.json; update the prose by hand:\n  {}",
            drift.join("\n  ")
        )
    }
}

fn find_bar_value(recovery: &Value, heading_substr: &str, bar_label: &str) -> Option<f64> {
    let groups: &Vec<Value> = recovery.get("groups")?.as_array()?;
    for group in groups {
        let Some(heading) = group.get("heading").and_then(Value::as_str) else {
            continue;
        };
        if !heading.contains(heading_substr) {
            continue;
        }
        let Some(bars) = group.get("bars").and_then(Value::as_array) else {
            continue;
        };
        for bar in bars {
            let Some(label) = bar.get("label").and_then(Value::as_str) else {
                continue;
            };
            if label == bar_label {
                return bar.get("value").and_then(Value::as_f64);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_bar_value_matches_heading_substring_and_exact_label() {
        let doc: Value = serde_json::json!({
            "groups": [
                {
                    "heading": "Python bytecode (CPython 3.14 stdlib)",
                    "bars": [
                        {"label": "200-module pinned corpus", "value": 94.18}
                    ]
                }
            ]
        });
        assert_eq!(
            find_bar_value(&doc, "Python bytecode", "200-module pinned corpus"),
            Some(94.18)
        );
        assert_eq!(
            find_bar_value(&doc, "Python bytecode", "missing label"),
            None
        );
        assert_eq!(
            find_bar_value(&doc, "no such heading", "200-module pinned corpus"),
            None
        );
    }

    #[test]
    fn pct2_formats_two_decimals() {
        assert_eq!(pct2(92.43), "92.43%");
        assert_eq!(pct2(94.0), "94.00%");
    }
}
