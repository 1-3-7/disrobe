#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    OriginalPosition, PositionResolver, RecoverOptions, RecoveredFile, RecoveryReport,
    SourceMapLocation, SourceTreeRecovery, decode_data_url_json, find_source_map,
    recover_source_map_json, recover_source_tree_from_js,
};
use serde_json::Value;

fn corpus_dir(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join("sourcemaps")
        .join(rel)
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p)
        .unwrap_or_else(|e: std::io::Error| panic!("read {}: {e}", p.display()))
}

#[derive(Debug, Clone)]
struct ExpectedSource {
    source: String,
    content: Option<String>,
}

fn expected_sources_from_map(map_json: &str) -> Vec<ExpectedSource> {
    let value: Value = serde_json::from_str(map_json).expect("oracle map parses as json");
    let mut out: Vec<ExpectedSource> = Vec::new();
    collect_expected(&value, &mut out);
    out
}

fn collect_expected(value: &Value, out: &mut Vec<ExpectedSource>) {
    if let Some(sections) = value.get("sections").and_then(Value::as_array) {
        for section in sections {
            if let Some(inner) = section.get("map") {
                collect_expected(inner, out);
            }
        }
        return;
    }
    let sources: &[Value] = value
        .get("sources")
        .and_then(Value::as_array)
        .map_or(&[], |v: &Vec<Value>| v.as_slice());
    let contents: &[Value] = value
        .get("sourcesContent")
        .and_then(Value::as_array)
        .map_or(&[], |v: &Vec<Value>| v.as_slice());
    for (index, source) in sources.iter().enumerate() {
        let source_name: String = source.as_str().unwrap_or_default().to_owned();
        let content: Option<String> = contents
            .get(index)
            .and_then(Value::as_str)
            .filter(|s: &&str| !s.is_empty())
            .map(str::to_owned);
        out.push(ExpectedSource {
            source: source_name,
            content,
        });
    }
}

fn basename(path: &str) -> &str {
    Path::new(path)
        .file_name()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .unwrap_or(path)
}

fn find_recovered<'a>(
    report: &'a RecoveryReport,
    source_basename: &str,
) -> Option<&'a RecoveredFile> {
    report
        .files
        .iter()
        .find(|f: &&RecoveredFile| basename(&f.relative_path) == source_basename)
}

fn assert_content_present_byte_identical(label: &str, report: &RecoveryReport, map_json: &str) {
    let expected: Vec<ExpectedSource> = expected_sources_from_map(map_json);
    let mut graded_content: usize = 0;
    let mut graded_absent: usize = 0;
    for exp in &expected {
        let base: &str = basename(&exp.source);
        let recovered: &RecoveredFile = find_recovered(report, base).unwrap_or_else(|| {
            panic!("{label}: every map source must yield a recovered entry, missing {base}")
        });
        if let Some(content) = &exp.content {
            assert_eq!(
                recovered.bytes,
                content.as_bytes(),
                "{label}/{base}: recovered bytes must equal the sourcesContent embedded in the real tool's map (byte-identical, data present)"
            );
            assert!(
                !recovered.reconstructed,
                "{label}/{base}: present content must not be flagged as a reconstructed stub"
            );
            graded_content += 1;
        } else {
            assert!(
                recovered.reconstructed,
                "{label}/{base}: absent content must yield an honest reconstructed stub, never fabricated source"
            );
            let stub_text: String =
                String::from_utf8(recovered.bytes.clone()).expect("stub is utf8");
            assert!(
                stub_text.contains("reconstructed skeleton"),
                "{label}/{base}: stub must carry the honest reconstruction banner, got {stub_text}"
            );
            graded_absent += 1;
        }
    }
    assert!(
        graded_content + graded_absent == expected.len() && !expected.is_empty(),
        "{label}: graded {graded_content} present + {graded_absent} absent of {} sources",
        expected.len()
    );
    assert!(
        report.mapped_segments > 0,
        "{label}: the real tool's VLQ mappings must decode to attributing segments"
    );
}

fn grade_map_file(label: &str, dir: &str, map_name: &str) {
    let map_path: PathBuf = corpus_dir(dir).join(map_name);
    let map_json: String = read(&map_path);
    let report: RecoveryReport = recover_source_map_json(&map_json, RecoverOptions::default())
        .unwrap_or_else(|e| panic!("{label}: recover_source_map_json failed: {e}"));
    assert_content_present_byte_identical(label, &report, &map_json);
}

fn grade_external_trailer(label: &str, dir: &str, bundle_name: &str, map_name: &str) {
    let dir_path: PathBuf = corpus_dir(dir);
    let bundle: String = read(&dir_path.join(bundle_name));
    let map_json: String = read(&dir_path.join(map_name));
    let recovery: SourceTreeRecovery =
        recover_source_tree_from_js(&bundle, RecoverOptions::default(), |url: &str| {
            std::fs::read_to_string(dir_path.join(basename(url))).ok()
        })
        .unwrap_or_else(|e| panic!("{label}: tree recovery failed: {e}"));
    assert!(
        matches!(recovery.location, SourceMapLocation::External { .. }),
        "{label}: bundle must carry an external //# sourceMappingURL trailer"
    );
    let report: RecoveryReport = recovery
        .report
        .unwrap_or_else(|| panic!("{label}: external map must resolve to a report"));
    assert_content_present_byte_identical(label, &report, &map_json);
}

fn grade_inline_trailer(label: &str, dir: &str, bundle_name: &str) {
    let bundle: String = read(&corpus_dir(dir).join(bundle_name));
    let info = find_source_map(&bundle)
        .unwrap_or_else(|| panic!("{label}: inline sourceMappingURL trailer must be present"));
    assert!(info.inline, "{label}: trailer must be a data: url");
    let map_json: String = decode_data_url_json(&info.url)
        .unwrap_or_else(|e| panic!("{label}: inline data url must decode: {e}"));
    let report: RecoveryReport = recover_source_map_json(&map_json, RecoverOptions::default())
        .unwrap_or_else(|e| panic!("{label}: recover failed: {e}"));
    assert_content_present_byte_identical(label, &report, &map_json);
}

#[test]
fn terser_compress_mangle_map_recovers_content_byte_identical() {
    grade_external_trailer("terser", "terser", "math.min.js", "math.min.js.map");
}

#[test]
fn esbuild_minify_external_map_recovers_full_tree_byte_identical() {
    grade_external_trailer(
        "esbuild-min",
        "esbuild-min",
        "bundle.min.js",
        "bundle.min.js.map",
    );
}

#[test]
fn esbuild_inline_data_uri_map_recovers_full_tree_byte_identical() {
    grade_inline_trailer("esbuild-inline", "esbuild-inline", "bundle.inline.js");
}

#[test]
fn esbuild_external_only_map_recovers_full_tree_byte_identical() {
    let bundle: String = read(&corpus_dir("esbuild-external").join("bundle.ext.js"));
    assert!(
        find_source_map(&bundle).is_none(),
        "esbuild --sourcemap=external deliberately emits no trailer; the .map is found on disk by convention"
    );
    grade_map_file("esbuild-external", "esbuild-external", "bundle.ext.js.map");
}

#[test]
fn esbuild_sourceroot_map_recovers_content_byte_identical_despite_url_root() {
    grade_external_trailer(
        "esbuild-sourceroot",
        "esbuild-sourceroot",
        "bundle.sr.js",
        "bundle.sr.js.map",
    );
}

#[test]
fn esbuild_sourceroot_paths_stay_inside_tree_and_are_not_absolute() {
    let dir_path: PathBuf = corpus_dir("esbuild-sourceroot");
    let map_json: String = read(&dir_path.join("bundle.sr.js.map"));
    let report: RecoveryReport =
        recover_source_map_json(&map_json, RecoverOptions::default()).expect("recover sourceroot");
    for file in &report.files {
        assert!(
            !file.relative_path.contains(".."),
            "sourceRoot must not let a path escape: {}",
            file.relative_path
        );
        assert!(
            !Path::new(&file.relative_path).is_absolute(),
            "recovered path must be relative: {}",
            file.relative_path
        );
        assert!(
            !file.relative_path.contains("://"),
            "the https sourceRoot scheme must be stripped: {}",
            file.relative_path
        );
    }
}

#[test]
fn rollup_sourcemap_recovers_full_tree_byte_identical() {
    grade_external_trailer("rollup-min", "rollup-min", "bundle.js", "bundle.js.map");
}

#[test]
fn webpack5_production_source_map_recovers_full_tree_byte_identical() {
    grade_external_trailer(
        "webpack5-prod",
        "webpack5-prod",
        "bundle.js",
        "bundle.js.map",
    );
}

#[test]
fn javascript_obfuscator_separate_map_recovers_embedded_content_byte_identical() {
    let dir_path: PathBuf = corpus_dir("jsobf-separate");
    let bundle: String = read(&dir_path.join("math.obf.js"));
    let map_json: String = read(&dir_path.join("math.obf.js.map"));
    let info = find_source_map(&bundle).expect("javascript-obfuscator appends an external trailer");
    assert_eq!(
        info.url, "math.js.map",
        "the trailer references a sourceMappingURL that differs from the on-disk file name; recovery must resolve it by convention"
    );
    let recovery: SourceTreeRecovery =
        recover_source_tree_from_js(&bundle, RecoverOptions::default(), |_url: &str| {
            std::fs::read_to_string(dir_path.join("math.obf.js.map")).ok()
        })
        .expect("tree recovery resolves the mismatched-name map");
    let report: RecoveryReport = recovery.report.expect("map resolves to a report");
    assert_content_present_byte_identical("jsobf-separate", &report, &map_json);
}

#[test]
fn javascript_obfuscator_inline_map_recovers_embedded_content_byte_identical() {
    grade_inline_trailer("jsobf-inline", "jsobf-inline", "math.obf.inline.js");
}

fn strip_query_and_fragment(url: &str) -> &str {
    let cut: usize = url.find(['?', '#']).unwrap_or(url.len());
    &url[..cut]
}

#[test]
fn trailer_with_query_string_at_eof_recovers_full_tree_byte_identical() {
    let dir_path: PathBuf = corpus_dir("edge-query");
    let bundle: String = read(&dir_path.join("app.js"));
    let map_json: String = read(&dir_path.join("bundle.min.js.map"));
    let info =
        find_source_map(&bundle).expect("a trailer at EOF with no trailing newline must be found");
    assert_eq!(
        info.url, "bundle.min.js.map?v=abc123",
        "find_source_map must surface the URL verbatim including the cache-busting query, leaving query handling to the resolver"
    );
    let recovery: SourceTreeRecovery =
        recover_source_tree_from_js(&bundle, RecoverOptions::default(), |url: &str| {
            std::fs::read_to_string(dir_path.join(basename(strip_query_and_fragment(url)))).ok()
        })
        .expect("query-aware resolver recovers the map");
    let report: RecoveryReport = recovery.report.expect("map resolves");
    assert_content_present_byte_identical("edge-query", &report, &map_json);
}

#[test]
fn sectioned_indexed_map_recovers_both_sections_byte_identical() {
    grade_external_trailer(
        "sectioned",
        "sectioned",
        "combined.min.js",
        "combined.min.js.map",
    );
}

#[test]
fn sectioned_indexed_map_resolves_second_section_token_to_its_original() {
    let dir_path: PathBuf = corpus_dir("sectioned");
    let bundle: String = read(&dir_path.join("combined.min.js"));
    let map_json: String = read(&dir_path.join("combined.min.js.map"));
    let resolver: PositionResolver =
        PositionResolver::from_json(&map_json).expect("resolver over composed sections");
    let first_section_lines: usize = {
        let value: Value = serde_json::from_str(&map_json).expect("parse");
        value["sections"][1]["offset"]["line"]
            .as_u64()
            .expect("section 1 offset line") as usize
    };
    let target_line: &str = bundle
        .split('\n')
        .nth(first_section_lines)
        .expect("second section line present in the concatenated bundle");
    assert!(
        !target_line.is_empty(),
        "second section must hold real generated code, not a blank line"
    );
    let gen_line: u32 = u32::try_from(first_section_lines).expect("line fits in u32");
    let in_line_col: u32 = u32::try_from(
        target_line
            .find("return")
            .or_else(|| target_line.find("function"))
            .expect("the math.js bundle keeps a return/function keyword"),
    )
    .expect("col fits in u32");
    let resolved: OriginalPosition = resolver
        .resolve(gen_line, in_line_col)
        .expect("a section 1 token position must resolve through the composed mapping");
    assert!(
        basename(&resolved.source).starts_with("math"),
        "the second section was an esbuild bundle of math.js; its tokens must map back to that math source (deduped basename allowed), got {}",
        resolved.source
    );
    assert_eq!(
        resolved.line, 1,
        "the canonical source-map oracle resolves this token to original line 1 (0-based); the composed mapping must agree"
    );
}

#[test]
fn nested_sectioned_map_recovers_all_flattened_sources_byte_identical() {
    grade_external_trailer(
        "nested-sectioned",
        "nested-sectioned",
        "nested.min.js",
        "nested.min.js.map",
    );
}

#[test]
fn nested_sectioned_map_resolves_tokens_matching_the_canonical_oracle() {
    let dir_path: PathBuf = corpus_dir("nested-sectioned");
    let map_json: String = read(&dir_path.join("nested.min.js.map"));
    let resolver: PositionResolver =
        PositionResolver::from_json(&map_json).expect("resolver over a nested section map");

    let math_first: OriginalPosition = resolver
        .resolve(0, 22)
        .expect("inner-inner section 0 (math) token resolves through two levels of nesting");
    assert!(
        basename(&math_first.source).starts_with("math"),
        "got {}",
        math_first.source
    );
    assert_eq!(
        (math_first.line, math_first.column),
        (1, 1),
        "canonical source-map oracle: gen (0,22) -> math.js original line 1 col 1 (0-based)"
    );

    let greet_token: OriginalPosition = resolver
        .resolve(1, 20)
        .expect("inner section 1 (greet) token resolves through the nested composition");
    assert!(
        basename(&greet_token.source).starts_with("greet"),
        "got {}",
        greet_token.source
    );
    assert_eq!(
        (greet_token.line, greet_token.column),
        (1, 2),
        "canonical source-map oracle: gen (1,20) -> greet.js original line 1 col 2 (0-based)"
    );

    let outer_math: OriginalPosition = resolver
        .resolve(2, 189)
        .expect("outer section 1 (index bundle) token resolves to a re-bundled math source");
    assert!(
        basename(&outer_math.source).starts_with("math"),
        "got {}",
        outer_math.source
    );
    assert_eq!(
        (outer_math.line, outer_math.column),
        (0, 7),
        "canonical source-map oracle: gen (2,189) -> math original line 0 col 7 (0-based)"
    );
}

#[test]
fn partial_content_map_recovers_present_and_stubs_absent_without_fabrication() {
    let map_path: PathBuf = corpus_dir("partial-content").join("partial.js.map");
    let map_json: String = read(&map_path);
    let report: RecoveryReport =
        recover_source_map_json(&map_json, RecoverOptions::default()).expect("recover partial");
    let present_count: usize = report
        .files
        .iter()
        .filter(|f: &&RecoveredFile| !f.reconstructed)
        .count();
    let stub_count: usize = report
        .files
        .iter()
        .filter(|f: &&RecoveredFile| f.reconstructed)
        .count();
    assert_eq!(
        present_count, 2,
        "two of three esbuild sources kept content and must recover byte-identical"
    );
    assert_eq!(
        stub_count, 1,
        "the one stripped source must become exactly one honest stub, never fabricated"
    );
    assert_content_present_byte_identical("partial-content", &report, &map_json);
    let greet: &RecoveredFile =
        find_recovered(&report, "greet.js").expect("greet.js entry present as a stub");
    assert!(greet.reconstructed);
    let stub: String = String::from_utf8(greet.bytes.clone()).expect("utf8 stub");
    assert!(
        !stub.contains("return `Hello"),
        "the stub must not fabricate the absent original body: {stub}"
    );
}
