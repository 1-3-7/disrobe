#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{
    ClosureAdvancedReport, PresetEnvUndoResult, TerserRestoreReport, restore_terser_mangled,
    undo_closure_advanced, undo_preset_env,
};

const TSC_TIMEOUT: Duration = Duration::from_secs(30);
const TSC_CAPTURE: usize = 1usize << 20;
const TSC_VERSION: &str = "Version 6.0.3";

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> Option<String> {
    let p: PathBuf = corpus_path(rel);
    if !p.exists() {
        return None;
    }
    fs::read_to_string(&p).ok()
}

fn required_corpus_path(rel: &str) -> PathBuf {
    let path: PathBuf = corpus_path(rel);
    assert!(
        path.is_file(),
        "required tracked TypeScript fixture is missing: {}",
        path.display()
    );
    path
}

fn typescript_compiler() -> PathBuf {
    std::env::var_os("DISROBE_TSC")
        .filter(|value: &OsString| !value.is_empty())
        .map_or_else(
            || PathBuf::from(if cfg!(windows) { "tsc.cmd" } else { "tsc" }),
            PathBuf::from,
        )
}

fn captured_diagnostics(captured: &CapturedOutput) -> String {
    format!(
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        captured.exit_code,
        String::from_utf8_lossy(&captured.stdout),
        String::from_utf8_lossy(&captured.stderr)
    )
}

fn require_typescript_version(compiler: &Path) -> Result<(), String> {
    let args: [OsString; 1] = [OsString::from("--version")];
    let captured: CapturedOutput = run_captured(compiler, &args, TSC_TIMEOUT, TSC_CAPTURE)
        .map_err(|error: std::io::Error| {
            format!(
                "TypeScript compiler is required but `{}` could not be launched: {error}. Install TypeScript or set DISROBE_TSC to the compiler executable",
                compiler.display()
            )
        })?
        .ok_or_else(|| {
            format!(
                "TypeScript compiler `{}` exceeded {TSC_TIMEOUT:?} while reporting its version",
                compiler.display()
            )
        })?;
    if captured.exit_code != Some(0i32) {
        return Err(format!(
            "TypeScript compiler `{}` could not report its version\n{}",
            compiler.display(),
            captured_diagnostics(&captured)
        ));
    }
    let actual_version: String = String::from_utf8_lossy(&captured.stdout).trim().to_owned();
    if actual_version != TSC_VERSION {
        return Err(format!(
            "TypeScript compiler `{}` reported `{actual_version}`, expected `{TSC_VERSION}`",
            compiler.display()
        ));
    }
    Ok(())
}

fn emit_with_typescript(
    compiler: &Path,
    input: &Path,
    output_dir: &Path,
) -> Result<CapturedOutput, String> {
    require_typescript_version(compiler)?;
    fs::create_dir_all(output_dir).map_err(|error: std::io::Error| {
        format!(
            "failed to create TypeScript output directory {}: {error}",
            output_dir.display()
        )
    })?;
    let args: Vec<OsString> = vec![
        OsString::from("--target"),
        OsString::from("es2022"),
        OsString::from("--module"),
        OsString::from("commonjs"),
        OsString::from("--lib"),
        OsString::from("es2022,dom"),
        OsString::from("--allowJs"),
        OsString::from("--declaration"),
        OsString::from("--sourceMap"),
        OsString::from("--noEmitOnError"),
        OsString::from("false"),
        OsString::from("--strict"),
        OsString::from("false"),
        OsString::from("--pretty"),
        OsString::from("false"),
        OsString::from("--outDir"),
        output_dir.as_os_str().to_owned(),
        input.as_os_str().to_owned(),
    ];
    let captured: CapturedOutput = run_captured(compiler, &args, TSC_TIMEOUT, TSC_CAPTURE)
        .map_err(|error: std::io::Error| {
            format!(
                "TypeScript compiler is required but `{}` could not be launched: {error}. Install TypeScript or set DISROBE_TSC to the compiler executable",
                compiler.display()
            )
        })?
        .ok_or_else(|| {
            format!(
                "TypeScript compiler `{}` exceeded {TSC_TIMEOUT:?} while checking {}",
                compiler.display(),
                input.display()
            )
        })?;
    if captured.exit_code.is_none() {
        return Err(format!(
            "TypeScript compiler `{}` terminated without an exit code while emitting {}\n{}",
            compiler.display(),
            input.display(),
            captured_diagnostics(&captured)
        ));
    }
    Ok(captured)
}

fn first_byte_difference(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right.iter())
        .position(|(left_byte, right_byte): (&u8, &u8)| left_byte != right_byte)
        .unwrap_or_else(|| left.len().min(right.len()))
}

fn compare_emitted_outputs(output_dir: &Path) -> Result<(), String> {
    let generated_javascript_path: PathBuf = output_dir.join("edge_cases.js");
    let generated_declaration_path: PathBuf = output_dir.join("edge_cases.d.ts");
    let generated_sourcemap_path: PathBuf = output_dir.join("edge_cases.js.map");
    for path in [
        &generated_javascript_path,
        &generated_declaration_path,
        &generated_sourcemap_path,
    ] {
        if !path.is_file() {
            return Err(format!(
                "required emitted TypeScript artifact is missing: {}",
                path.display()
            ));
        }
    }

    let tracked_declaration_path: PathBuf = required_corpus_path("tsc/edge_cases.d.ts");
    let tracked_declaration: Vec<u8> =
        fs::read(&tracked_declaration_path).map_err(|error: std::io::Error| {
            format!(
                "failed to read tracked declaration {}: {error}",
                tracked_declaration_path.display()
            )
        })?;
    let generated_declaration: Vec<u8> =
        fs::read(&generated_declaration_path).map_err(|error: std::io::Error| {
            format!(
                "failed to read emitted declaration {}: {error}",
                generated_declaration_path.display()
            )
        })?;
    if generated_declaration != tracked_declaration {
        let offset: usize = first_byte_difference(&tracked_declaration, &generated_declaration);
        return Err(format!(
            "emitted declaration differs from {} at byte {offset}: tracked {} bytes, emitted {} bytes",
            tracked_declaration_path.display(),
            tracked_declaration.len(),
            generated_declaration.len()
        ));
    }

    let tracked_javascript_path: PathBuf = required_corpus_path("tsc/obfuscated.megafile.js");
    let tracked_javascript: String =
        fs::read_to_string(&tracked_javascript_path).map_err(|error: std::io::Error| {
            format!(
                "failed to read tracked JavaScript {}: {error}",
                tracked_javascript_path.display()
            )
        })?;
    let generated_javascript: String =
        fs::read_to_string(&generated_javascript_path).map_err(|error: std::io::Error| {
            format!(
                "failed to read emitted JavaScript {}: {error}",
                generated_javascript_path.display()
            )
        })?;
    let tracked_lines: Vec<&str> = tracked_javascript
        .lines()
        .filter(|line: &&str| !line.is_empty())
        .collect();
    let generated_lines: Vec<&str> = generated_javascript
        .lines()
        .filter(|line: &&str| !line.is_empty())
        .collect();
    if generated_lines != tracked_lines {
        let line_index: usize = tracked_lines
            .iter()
            .zip(generated_lines.iter())
            .position(|(tracked, generated): (&&str, &&str)| tracked != generated)
            .unwrap_or_else(|| tracked_lines.len().min(generated_lines.len()));
        return Err(format!(
            "emitted JavaScript differs from {} at nonempty line {}: tracked {:?}, emitted {:?}",
            tracked_javascript_path.display(),
            line_index + 1usize,
            tracked_lines.get(line_index),
            generated_lines.get(line_index)
        ));
    }
    Ok(())
}

#[test]
fn real_terser_megafile_restore_runs_without_panic() {
    let Some(src): Option<String> = load("terser/obfuscated.megafile.js") else {
        return;
    };
    let report: TerserRestoreReport = restore_terser_mangled(&src);
    let _ = report;
}

#[test]
fn real_closure_simple_megafile_undo_runs_without_panic() {
    let Some(src): Option<String> = load("closure/obfuscated.megafile.simple.js") else {
        return;
    };
    let report: ClosureAdvancedReport = undo_closure_advanced(&src);
    let _ = report;
}

#[test]
fn real_closure_whitespace_megafile_undo_runs_without_panic() {
    let Some(src): Option<String> = load("closure/obfuscated.megafile.whitespace.js") else {
        return;
    };
    let report: ClosureAdvancedReport = undo_closure_advanced(&src);
    let _ = report;
}

#[test]
fn real_babel_preset_env_megafile_undo_runs_without_panic() {
    let Some(src): Option<String> = load("babel-preset-env/obfuscated.megafile.js") else {
        return;
    };
    let report: PresetEnvUndoResult = undo_preset_env(&src);
    let _ = report;
}

#[test]
fn real_tsc_manifest_outputs_match_tracked_artifacts() {
    let compiler: PathBuf = typescript_compiler();
    let input: PathBuf = required_corpus_path("tsc/edge_cases.ts");
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_tsc_manifest_outputs").expect("create scratch directory");
    let output_dir: PathBuf = scratch.path().join("out");
    let captured: CapturedOutput = emit_with_typescript(&compiler, &input, &output_dir)
        .unwrap_or_else(|diagnostic: String| panic!("{diagnostic}"));
    compare_emitted_outputs(&output_dir).unwrap_or_else(|difference: String| {
        panic!("{difference}\n{}", captured_diagnostics(&captured));
    });
    scratch.close().expect("remove scratch directory");
}

#[test]
fn typescript_output_oracle_rejects_corrupted_input() {
    let compiler: PathBuf = typescript_compiler();
    let tracked_input: PathBuf = required_corpus_path("tsc/edge_cases.ts");
    let scratch: ScratchDir =
        ScratchDir::create("disrobe_tsc_mutation").expect("create scratch directory");
    let mutation_input: PathBuf = scratch.path().join("edge_cases.ts");
    let mut source: String =
        fs::read_to_string(&tracked_input).expect("read tracked TypeScript input");
    source.push_str("\ndeclare const broken: ;\n");
    fs::write(&mutation_input, source).expect("write corrupted TypeScript input");
    let output_dir: PathBuf = scratch.path().join("out");
    let captured: CapturedOutput = emit_with_typescript(&compiler, &mutation_input, &output_dir)
        .unwrap_or_else(|diagnostic: String| panic!("{diagnostic}"));
    let diagnostics: String = captured_diagnostics(&captured);
    assert!(diagnostics.contains("error TS1110:"), "{diagnostics}");
    let difference: String = compare_emitted_outputs(&output_dir)
        .expect_err("corrupted TypeScript input must not match tracked artifacts");
    assert!(
        difference.contains("required emitted TypeScript artifact is missing")
            || difference.contains("differs from"),
        "{difference}"
    );
    scratch.close().expect("remove scratch directory");
}

#[test]
fn real_outputs_distinct_from_input() {
    let Some(input): Option<String> = load("terser/edge_cases.js") else {
        return;
    };
    for rel in [
        "terser/obfuscated.megafile.js",
        "closure/obfuscated.megafile.simple.js",
        "closure/obfuscated.megafile.whitespace.js",
        "babel-preset-env/obfuscated.megafile.js",
    ] {
        let Some(out): Option<String> = load(rel) else {
            continue;
        };
        assert_ne!(out, input, "{rel} must not equal input");
    }
}
