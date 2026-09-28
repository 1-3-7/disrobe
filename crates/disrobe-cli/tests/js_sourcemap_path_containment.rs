#![cfg(feature = "js")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::{Path, PathBuf};

use common::{Run, run_disrobe, temp_dir, write_bytes};

const OUTSIDE_MAP: &str = r#"{"version":3,"file":"app.js","sources":["secret.js"],"sourcesContent":["export const SECRET = 1;\n"],"names":[],"mappings":"AAAA"}"#;

fn bundle_referencing(url: &str) -> String {
    format!("console.log(1);\n//# sourceMappingURL={url}\n")
}

fn run_sourcemap(input: &Path, out: &Path) -> Run {
    run_disrobe(&[
        "js",
        "sourcemap",
        input.to_str().expect("utf-8 input path"),
        "--out",
        out.to_str().expect("utf-8 out path"),
    ])
}

#[test]
fn a_source_map_reference_outside_the_input_directory_is_refused_by_name() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("js-sourcemap-containment");
    let root: PathBuf = scratch.path().to_path_buf();
    let outside_map: PathBuf = root.join("outside.map");
    write_bytes(&outside_map, OUTSIDE_MAP.as_bytes());
    let absolute: String = outside_map.to_str().expect("utf-8 path").to_owned();
    let cases: [(&str, String); 3] = [
        ("parent", "../outside.map".to_owned()),
        ("absolute", absolute),
        (
            "unc",
            r"\\disrobe-test.invalid\share\outside.map".to_owned(),
        ),
    ];
    for (label, url) in cases {
        let input: PathBuf = root.join(label).join("app.js");
        write_bytes(&input, bundle_referencing(&url).as_bytes());
        let out: PathBuf = root.join(format!("{label}-out"));
        let run: Run = run_sourcemap(&input, &out);
        assert_ne!(
            run.code, 0,
            "{label}: `{url}` names a map outside the input directory and must be refused\nstdout:\n{}",
            run.stdout
        );
        assert!(
            run.stderr.contains("DR-CLI-0108"),
            "{label}: the refusal must be the typed DR-CLI-0108\nstderr:\n{}",
            run.stderr
        );
        assert!(
            !out.join("secret.js").exists(),
            "{label}: nothing from the outside map may be written"
        );
    }
}

#[test]
fn a_source_map_beside_the_input_is_still_followed() {
    let scratch: disrobe_core::scratch::ScratchDir = temp_dir("js-sourcemap-sibling");
    let root: PathBuf = scratch.path().to_path_buf();
    write_bytes(&root.join("in").join("app.js.map"), OUTSIDE_MAP.as_bytes());
    let input: PathBuf = root.join("in").join("app.js");
    write_bytes(&input, bundle_referencing("app.js.map").as_bytes());
    let out: PathBuf = root.join("sibling-out");
    let run: Run = run_sourcemap(&input, &out);
    assert_eq!(run.code, 0, "stderr:\n{}", run.stderr);
    let recovered: String = std::fs::read_to_string(out.join("secret.js"))
        .expect("the sibling map's source is written");
    assert_eq!(recovered, "export const SECRET = 1;\n");
}
