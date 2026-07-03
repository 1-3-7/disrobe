#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_js_deob::{
    OriginalPosition, PositionResolver, RecoverOptions, RecoveredFile, RecoveryReport,
    SourceMapLocation, SourceTreeRecovery, decode_data_url_json, find_source_map,
    recover_source_map_json, recover_source_tree_from_js, write_recovered_sources,
};

fn npx() -> Option<String> {
    for candidate in ["npx", "npx.cmd"] {
        let probe: std::io::Result<std::process::Output> =
            Command::new(candidate).arg("--version").output();
        if probe.is_ok_and(|o: std::process::Output| o.status.success()) {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn run_esbuild(npx_bin: &str, args: &[&str], cwd: &Path) -> Option<std::process::Output> {
    let mut command: Command = Command::new(npx_bin);
    command.arg("-y").arg("esbuild").args(args).current_dir(cwd);
    match command.output() {
        Ok(out) if out.status.success() => Some(out),
        Ok(out) => {
            eprintln!(
                "skip: esbuild exited {:?}: {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
            None
        }
        Err(e) => {
            eprintln!("skip: cannot spawn esbuild via {npx_bin}: {e}");
            None
        }
    }
}

static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn temp_dir(tag: &str) -> PathBuf {
    let seq: u64 = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let base: PathBuf =
        std::env::temp_dir().join(format!("disrobe-sm-{tag}-{}-{seq}", std::process::id()));
    std::fs::create_dir_all(&base).expect("mkdir temp");
    base
}

#[test]
fn esbuild_map_recovers_original_sources_byte_for_byte() {
    let Some(npx_bin): Option<String> = npx() else {
        eprintln!("skip: npx not on PATH; cannot generate a real esbuild source map");
        return;
    };
    let work: PathBuf = temp_dir("esbuild");
    let src: PathBuf = work.join("src");
    std::fs::create_dir_all(&src).expect("mkdir src");

    let index_body: &str = "import { add } from './util';\nconsole.log(add(2, 3));\n";
    let util_body: &str = "export function add(a, b) {\n  return a + b;\n}\n";
    std::fs::write(src.join("index.js"), index_body).expect("write index");
    std::fs::write(src.join("util.js"), util_body).expect("write util");

    let out_js: PathBuf = work.join("bundle.js");
    let Some(_) = run_esbuild(
        &npx_bin,
        &[
            "src/index.js",
            "--bundle",
            "--sourcemap",
            &format!("--outfile={}", out_js.display()),
        ],
        &work,
    ) else {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
        return;
    };

    let map_path: PathBuf = work.join("bundle.js.map");
    assert!(
        map_path.exists(),
        "esbuild must emit bundle.js.map next to the bundle"
    );
    let raw_json: String = std::fs::read_to_string(&map_path).expect("read map");

    let report: RecoveryReport =
        recover_source_map_json(&raw_json, RecoverOptions::default()).expect("recover");
    assert!(
        report.with_content >= 2,
        "esbuild embeds sourcesContent; expected >=2 recovered files, got {}",
        report.with_content
    );

    let index: &RecoveredFile = report
        .files
        .iter()
        .find(|f: &&RecoveredFile| f.relative_path.ends_with("index.js"))
        .expect("recovered index.js");
    let util: &RecoveredFile = report
        .files
        .iter()
        .find(|f: &&RecoveredFile| f.relative_path.ends_with("util.js"))
        .expect("recovered util.js");
    assert_eq!(
        index.bytes,
        index_body.as_bytes(),
        "index.js must round-trip byte-for-byte from the real esbuild map"
    );
    assert_eq!(
        util.bytes,
        util_body.as_bytes(),
        "util.js must round-trip byte-for-byte from the real esbuild map"
    );
    assert!(!index.reconstructed && !util.reconstructed);

    let out_root: PathBuf = work.join("recovered");
    let written: BTreeMap<String, PathBuf> =
        write_recovered_sources(&out_root, &report).expect("write recovered tree");
    for path in written.values() {
        assert!(path.exists(), "written file must exist: {}", path.display());
        let canonical: PathBuf = path.canonicalize().expect("canonicalize written file");
        let root_canonical: PathBuf = out_root.canonicalize().expect("canonicalize root");
        assert!(
            canonical.starts_with(&root_canonical),
            "every written file must stay inside the output dir: {}",
            canonical.display()
        );
    }
    let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
}

#[test]
fn esbuild_inline_map_extracted_from_js_comment() {
    let Some(npx_bin): Option<String> = npx() else {
        eprintln!("skip: npx not on PATH");
        return;
    };
    let work: PathBuf = temp_dir("inline");
    std::fs::write(work.join("only.js"), "export const greeting = 'hi';\n").expect("write only");

    let out_js: PathBuf = work.join("inline.js");
    let Some(_) = run_esbuild(
        &npx_bin,
        &[
            "only.js",
            "--bundle",
            "--sourcemap=inline",
            &format!("--outfile={}", out_js.display()),
        ],
        &work,
    ) else {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
        return;
    };

    let js_text: String = std::fs::read_to_string(&out_js).expect("read inline bundle");
    let info = find_source_map(&js_text).expect("inline sourceMappingURL must be present");
    assert!(info.inline, "esbuild inline map must be a data: url");
    let raw_json: String = decode_data_url_json(&info.url).expect("decode inline data url");

    let report: RecoveryReport =
        recover_source_map_json(&raw_json, RecoverOptions::default()).expect("recover inline");
    let only: &RecoveredFile = report
        .files
        .iter()
        .find(|f: &&RecoveredFile| f.relative_path.ends_with("only.js"))
        .expect("recovered only.js");
    assert_eq!(only.bytes, b"export const greeting = 'hi';\n");
    let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
}

#[test]
fn esbuild_full_tree_reconstructed_from_js_sourcemapping_url_trailer() {
    let Some(npx_bin): Option<String> = npx() else {
        eprintln!("skip: npx not on PATH; cannot generate a real esbuild source map");
        return;
    };
    let work: PathBuf = temp_dir("tree");
    let src: PathBuf = work.join("src");
    std::fs::create_dir_all(&src).expect("mkdir src");

    let originals: [(&str, &str); 3] = [
        (
            "index.js",
            "import { add } from './math/add';\nimport { tag } from './util/tag';\nconsole.log(tag(add(2, 3)));\n",
        ),
        (
            "math/add.js",
            "export function add(a, b) {\n  return a + b;\n}\n",
        ),
        (
            "util/tag.js",
            "export function tag(value) {\n  return `[${value}]`;\n}\n",
        ),
    ];
    for (rel, body) in &originals {
        let dest: PathBuf = src.join(rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).expect("mkdir nested src");
        }
        std::fs::write(&dest, body).expect("write original");
    }

    let out_js: PathBuf = work.join("bundle.js");
    let Some(_) = run_esbuild(
        &npx_bin,
        &[
            "src/index.js",
            "--bundle",
            "--sourcemap",
            &format!("--outfile={}", out_js.display()),
        ],
        &work,
    ) else {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
        return;
    };

    let bundle_text: String = std::fs::read_to_string(&out_js).expect("read bundle");
    let map_dir: PathBuf = out_js.parent().expect("bundle has a parent").to_path_buf();
    let recovery: SourceTreeRecovery =
        recover_source_tree_from_js(&bundle_text, RecoverOptions::default(), |url: &str| {
            std::fs::read_to_string(map_dir.join(url)).ok()
        })
        .expect("recover tree from js trailer");

    assert!(
        matches!(recovery.location, SourceMapLocation::External { .. }),
        "esbuild --sourcemap emits an external //# sourceMappingURL trailer"
    );
    let report: RecoveryReport = recovery
        .report
        .expect("the external map next to the bundle must resolve");

    let mut matched: usize = 0;
    for (rel, body) in &originals {
        let basename: &str = std::path::Path::new(rel)
            .file_name()
            .and_then(|s: &std::ffi::OsStr| s.to_str())
            .expect("basename");
        let recovered: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path.ends_with(basename))
            .unwrap_or_else(|| panic!("recovered {basename} from the real esbuild tree"));
        assert_eq!(
            recovered.bytes,
            body.as_bytes(),
            "{basename} must round-trip byte-for-byte from the real esbuild map"
        );
        assert!(!recovered.reconstructed, "{basename} had sourcesContent");
        assert!(
            recovered.coverage.mapped_segments > 0,
            "{basename} must own at least one decoded mapping segment"
        );
        matched += 1;
    }
    assert_eq!(
        matched, 3,
        "all three pre-bundle originals must reconstruct byte-identical from the bundle's trailer"
    );
    assert!(
        report.mapped_segments > 0,
        "the decoded VLQ mappings must attribute generated ranges to originals"
    );

    let out_root: PathBuf = work.join("recovered");
    let written: BTreeMap<String, PathBuf> =
        write_recovered_sources(&out_root, &report).expect("write recovered tree");
    let root_canonical: PathBuf = out_root.canonicalize().expect("canonicalize root");
    for path in written.values() {
        let canonical: PathBuf = path.canonicalize().expect("canonicalize written file");
        assert!(
            canonical.starts_with(&root_canonical),
            "every written file must stay inside the output dir: {}",
            canonical.display()
        );
    }
    let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
}

fn count_lines(text: &str) -> usize {
    text.split('\n').count()
}

#[test]
fn real_esbuild_maps_wrapped_in_indexed_section_map_reconstruct_both_sections() {
    let Some(npx_bin): Option<String> = npx() else {
        eprintln!("skip: npx not on PATH; cannot generate real esbuild maps");
        return;
    };
    let work: PathBuf = temp_dir("sectioned");
    let src: PathBuf = work.join("src");
    std::fs::create_dir_all(&src).expect("mkdir src");

    let alpha_body: &str = "export function alphaFn(a, b) {\n  return a + b;\n}\n";
    let beta_body: &str = "export const betaConst = (n) => n * 2 + 1;\n";
    std::fs::write(src.join("alpha.js"), alpha_body).expect("write alpha");
    std::fs::write(src.join("beta.js"), beta_body).expect("write beta");
    std::fs::write(
        src.join("entry_a.js"),
        "import { alphaFn } from './alpha';\nconsole.log(alphaFn(2, 3));\n",
    )
    .expect("write entry_a");
    std::fs::write(
        src.join("entry_b.js"),
        "import { betaConst } from './beta';\nconsole.log(betaConst(4));\n",
    )
    .expect("write entry_b");

    let out_a: PathBuf = work.join("a.js");
    let out_b: PathBuf = work.join("b.js");
    for (entry, out) in [("src/entry_a.js", &out_a), ("src/entry_b.js", &out_b)] {
        let Some(_) = run_esbuild(
            &npx_bin,
            &[
                entry,
                "--bundle",
                "--sourcemap",
                &format!("--outfile={}", out.display()),
            ],
            &work,
        ) else {
            let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
            return;
        };
    }

    let bundle_a: String = std::fs::read_to_string(&out_a).expect("read a.js");
    let map_a: String = std::fs::read_to_string(work.join("a.js.map")).expect("read a.js.map");
    let map_b: String = std::fs::read_to_string(work.join("b.js.map")).expect("read b.js.map");

    let section_b_line: usize = count_lines(&bundle_a);
    let indexed: String = format!(
        r#"{{"version":3,"file":"combined.js","sections":[{{"offset":{{"line":0,"column":0}},"map":{map_a}}},{{"offset":{{"line":{section_b_line},"column":0}},"map":{map_b}}}]}}"#
    );

    let report: RecoveryReport =
        recover_source_map_json(&indexed, RecoverOptions::default()).expect("recover sectioned");
    assert!(
        report.mapped_segments > 0,
        "composed sectioned mappings must decode to real segments"
    );

    for (basename, body) in [("alpha.js", alpha_body), ("beta.js", beta_body)] {
        let recovered: &RecoveredFile = report
            .files
            .iter()
            .find(|f: &&RecoveredFile| f.relative_path.ends_with(basename))
            .unwrap_or_else(|| panic!("recovered {basename} from the indexed section map"));
        assert_eq!(
            recovered.bytes,
            body.as_bytes(),
            "{basename} must reconstruct byte-identical through the composed indexed map"
        );
    }

    let resolver: PositionResolver =
        PositionResolver::from_json(&indexed).expect("resolver over composed sections");
    let (a_line, a_col): (u32, u32) =
        locate_token(&bundle_a, "alphaFn").expect("alphaFn in bundle a");
    let resolved_alpha: OriginalPosition = resolver
        .resolve(a_line, a_col)
        .expect("alphaFn resolves through section 0");
    assert!(
        resolved_alpha.source.ends_with("alpha.js"),
        "alphaFn must map to alpha.js, got {}",
        resolved_alpha.source
    );

    let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
}

#[test]
fn real_esbuild_map_with_injected_debug_id_is_surfaced() {
    let Some(npx_bin): Option<String> = npx() else {
        eprintln!("skip: npx not on PATH; cannot generate a real esbuild map");
        return;
    };
    let work: PathBuf = temp_dir("debugid");
    std::fs::write(work.join("only.js"), "export const greeting = 'hi';\n").expect("write only");
    let out_js: PathBuf = work.join("out.js");
    let Some(_) = run_esbuild(
        &npx_bin,
        &[
            "only.js",
            "--bundle",
            "--sourcemap",
            &format!("--outfile={}", out_js.display()),
        ],
        &work,
    ) else {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
        return;
    };
    let raw_json: String = std::fs::read_to_string(work.join("out.js.map")).expect("read map");
    let debug_id: &str = "85314830-023f-4cf1-a267-535f4e37bb17";
    let with_id: String = raw_json
        .trim_end()
        .strip_suffix('}')
        .map(|head: &str| format!(r#"{head},"debugId":"{debug_id}"}}"#))
        .expect("map json ends in a brace");
    let report: RecoveryReport =
        recover_source_map_json(&with_id, RecoverOptions::default()).expect("recover with debugId");
    assert_eq!(
        report.debug_id.as_deref(),
        Some(debug_id),
        "an injected debugId must be surfaced in the recovery report"
    );
    let only: &RecoveredFile = report
        .files
        .iter()
        .find(|f: &&RecoveredFile| f.relative_path.ends_with("only.js"))
        .expect("recovered only.js");
    assert_eq!(only.bytes, b"export const greeting = 'hi';\n");
    let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
}

fn locate_token(haystack: &str, token: &str) -> Option<(u32, u32)> {
    for (line_index, line) in haystack.split('\n').enumerate() {
        if let Some(byte_col) = line.find(token) {
            let char_col: usize = line[..byte_col].chars().count();
            let line_u32: u32 = u32::try_from(line_index).ok()?;
            let col_u32: u32 = u32::try_from(char_col).ok()?;
            return Some((line_u32, col_u32));
        }
    }
    None
}

#[test]
fn esbuild_map_resolves_generated_position_to_original_line_col() {
    let Some(npx_bin): Option<String> = npx() else {
        eprintln!("skip: npx not on PATH; cannot generate a real esbuild source map");
        return;
    };
    let work: PathBuf = temp_dir("resolve");
    let src: PathBuf = work.join("src");
    std::fs::create_dir_all(&src).expect("mkdir src");

    let index_body: &str =
        "import { uniqueAdderFn } from './util';\nconsole.log(uniqueAdderFn(2, 3));\n";
    let util_body: &str = "export function uniqueAdderFn(a, b) {\n  return a + b;\n}\n";
    std::fs::write(src.join("index.js"), index_body).expect("write index");
    std::fs::write(src.join("util.js"), util_body).expect("write util");

    let out_js: PathBuf = work.join("bundle.js");
    let Some(_) = run_esbuild(
        &npx_bin,
        &[
            "src/index.js",
            "--bundle",
            "--sourcemap",
            &format!("--outfile={}", out_js.display()),
        ],
        &work,
    ) else {
        let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
        return;
    };

    let bundle_text: String = std::fs::read_to_string(&out_js).expect("read bundle");
    let map_path: PathBuf = work.join("bundle.js.map");
    let raw_json: String = std::fs::read_to_string(&map_path).expect("read map");

    let resolver: PositionResolver =
        PositionResolver::from_json(&raw_json).expect("build resolver");

    let (gen_line, gen_col): (u32, u32) =
        locate_token(&bundle_text, "uniqueAdderFn").expect("token present in bundle");
    let resolved: OriginalPosition = resolver
        .resolve(gen_line, gen_col)
        .expect("generated position must resolve to an original position");

    let (orig_line, orig_col): (u32, u32) =
        locate_token(util_body, "uniqueAdderFn").expect("token in original util.js");

    assert!(
        resolved.source.ends_with("util.js"),
        "first definition of uniqueAdderFn must map to util.js, got {}",
        resolved.source
    );
    assert_eq!(
        (resolved.line, resolved.column),
        (orig_line, orig_col),
        "resolved original line/col must equal the token position in the pre-bundle util.js"
    );
    let _: std::io::Result<()> = std::fs::remove_dir_all(&work);
}
