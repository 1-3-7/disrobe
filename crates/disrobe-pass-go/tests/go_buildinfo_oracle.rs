#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::process::Command;

use disrobe_pass_go::{GoAnalysis, GoBuildInfo, GoModule, analyze};

#[derive(Debug, Default, PartialEq, Eq)]
struct OracleBuildInfo {
    go_version: Option<String>,
    path: Option<String>,
    main: Option<OracleModule>,
    deps: Vec<OracleModule>,
    settings: BTreeMap<String, String>,
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
struct OracleModule {
    path: String,
    version: String,
    sum: String,
    replace: Option<Box<Self>>,
}

fn go_on_path() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn oracle_via_toolchain(fixture: &str) -> Option<OracleBuildInfo> {
    if !go_on_path() {
        return None;
    }
    let path: std::path::PathBuf = common::fixture_path(fixture);
    let out: std::process::Output = Command::new("go")
        .args(["version", "-m"])
        .arg(&path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_go_version_m(&String::from_utf8_lossy(&out.stdout)))
}

enum Last {
    None,
    Main,
    Dep(usize),
}

fn parse_go_version_m(text: &str) -> OracleBuildInfo {
    let mut info: OracleBuildInfo = OracleBuildInfo::default();
    let mut last: Last = Last::None;
    for raw in text.lines() {
        if let Some(rest) = raw.strip_prefix('\t') {
            if let Some(v) = rest.strip_prefix("path\t") {
                info.path = Some(v.to_owned());
            } else if let Some(v) = rest.strip_prefix("mod\t") {
                info.main = Some(parse_oracle_module(v));
                last = Last::Main;
            } else if let Some(v) = rest.strip_prefix("dep\t") {
                info.deps.push(parse_oracle_module(v));
                last = Last::Dep(info.deps.len() - 1);
            } else if let Some(v) = rest.strip_prefix("=>\t") {
                let replacement: OracleModule = parse_oracle_module(v);
                match last {
                    Last::Main => {
                        if let Some(m) = info.main.as_mut() {
                            m.replace = Some(Box::new(replacement));
                        }
                    }
                    Last::Dep(idx) => {
                        if let Some(m) = info.deps.get_mut(idx) {
                            m.replace = Some(Box::new(replacement));
                        }
                    }
                    Last::None => {}
                }
                last = Last::None;
            } else if let Some(v) = rest.strip_prefix("build\t")
                && let Some((k, val)) = v.split_once('=')
            {
                info.settings.insert(k.to_owned(), val.to_owned());
            }
        } else if let Some(v) = raw.split_once(": go") {
            info.go_version = Some(format!("go{}", v.1.trim()));
        }
    }
    info
}

fn parse_oracle_module(line: &str) -> OracleModule {
    let cols: Vec<&str> = line.split('\t').collect();
    OracleModule {
        path: cols.first().copied().unwrap_or("").to_owned(),
        version: cols.get(1).copied().unwrap_or("").to_owned(),
        sum: cols.get(2).copied().unwrap_or("").to_owned(),
        replace: None,
    }
}

fn to_oracle_module(m: &GoModule) -> OracleModule {
    OracleModule {
        path: m.path.clone(),
        version: m.version.clone(),
        sum: m.sum.clone(),
        replace: m.replace.as_deref().map(to_oracle_module).map(Box::new),
    }
}

fn recovered_as_oracle(bi: &GoBuildInfo) -> OracleBuildInfo {
    OracleBuildInfo {
        go_version: bi.go_version.clone(),
        path: bi.path.clone(),
        main: bi.main.as_ref().map(to_oracle_module),
        deps: bi.deps.iter().map(to_oracle_module).collect(),
        settings: bi.settings.clone(),
    }
}

fn analyze_fixture(name: &str) -> Option<GoAnalysis> {
    let bytes: Vec<u8> = common::fixture_or_skip(name)?;
    Some(analyze(&bytes).expect("analyze fixture"))
}

const BUILDINFO_SOURCE: &str = r#"package main

import (
	"fmt"
	"os"
	"runtime"
)

func main() {
	fmt.Fprintln(os.Stdout, runtime.GOOS, runtime.GOARCH, runtime.Version())
}
"#;

#[test]
fn buildinfo_matches_go_version_m_on_fresh_real_build() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("buildinfo");
    common::write_module(&scratch, "disrobe.example/buildinfo", BUILDINFO_SOURCE);
    let Some(binary): Option<std::path::PathBuf> = common::go_build(&scratch, "buildinfo.exe", &[])
    else {
        panic!("go build (buildinfo) failed; the real-toolchain oracle cannot run");
    };

    let oracle: common::GoVersionM =
        common::go_version_m(&binary).expect("go version -m must produce the build-info oracle");

    let bytes: Vec<u8> = std::fs::read(&binary).expect("read buildinfo build");
    let analysis: GoAnalysis = analyze(&bytes).expect("analyze buildinfo build");
    let bi: &GoBuildInfo = analysis
        .moduledata
        .build_info
        .as_ref()
        .expect("a real go build embeds a build-info blob");

    assert_eq!(
        bi.path.as_deref(),
        oracle.path.as_deref(),
        "recovered module path must match `go version -m` on the same fresh binary"
    );
    assert_eq!(
        bi.go_version, oracle.go_version,
        "recovered go toolchain version must match `go version -m`"
    );
    assert_eq!(
        bi.settings, oracle.settings,
        "recovered build settings (GOOS/GOARCH/compiler/buildmode/...) must match `go version -m` exactly"
    );
    assert_eq!(bi.goos(), Some("windows"));
    assert_eq!(bi.goarch(), Some("amd64"));
    assert_eq!(
        analysis.buildversion, oracle.go_version,
        "GoAnalysis.buildversion must prefer the authoritative build-info go version"
    );
}

#[test]
fn buildinfo_matches_go_toolchain_oracle_on_embed_fixture() {
    let Some(analysis): Option<GoAnalysis> = analyze_fixture(common::HELLO_EMBED) else {
        return;
    };
    let bi: &GoBuildInfo = analysis
        .moduledata
        .build_info
        .as_ref()
        .expect("embed fixture carries an embedded build-info blob");

    let Some(oracle): Option<OracleBuildInfo> = oracle_via_toolchain(common::HELLO_EMBED) else {
        assert_eq!(bi.path.as_deref(), Some("embedfix"));
        assert_eq!(bi.goos(), Some("windows"));
        assert_eq!(bi.goarch(), Some("amd64"));
        assert_eq!(bi.vcs(), Some("git"));
        return;
    };

    let recovered: OracleBuildInfo = recovered_as_oracle(bi);
    assert_eq!(
        recovered.path, oracle.path,
        "recovered module path must match `go version -m`"
    );
    assert_eq!(
        recovered.main, oracle.main,
        "recovered main module must match the toolchain oracle"
    );
    assert_eq!(
        recovered.go_version, oracle.go_version,
        "recovered go version must match the toolchain oracle"
    );
    assert_eq!(
        recovered.settings, oracle.settings,
        "recovered build settings (GOOS/GOARCH/compiler/VCS/...) must match `go version -m` exactly"
    );
}

#[test]
fn buildinfo_recovers_deps_and_replace_matching_oracle() {
    let Some(analysis): Option<GoAnalysis> = analyze_fixture(common::HELLO_DEPS) else {
        return;
    };
    let bi: &GoBuildInfo = analysis
        .moduledata
        .build_info
        .as_ref()
        .expect("deps fixture carries an embedded build-info blob");

    let Some(oracle): Option<OracleBuildInfo> = oracle_via_toolchain(common::HELLO_DEPS) else {
        assert_eq!(bi.path.as_deref(), Some("depfix"));
        assert_eq!(bi.deps.len(), 1, "depfix requires exactly one dependency");
        assert_eq!(bi.deps[0].path, "example.com/depmod");
        assert!(
            bi.deps[0].replace.is_some(),
            "the local `replace` directive must surface on the dependency"
        );
        return;
    };

    let recovered: OracleBuildInfo = recovered_as_oracle(bi);
    assert_eq!(
        recovered.deps, oracle.deps,
        "recovered dependency list (incl. the `=>` replace directive) must match `go version -m`"
    );
    assert_eq!(recovered.main, oracle.main);
    assert_eq!(recovered.settings, oracle.settings);
    assert!(
        recovered.deps.first().is_some_and(|d| d.replace.is_some()),
        "the replace directive must be attached to the dependency, not dropped"
    );
}

#[test]
fn buildinfo_surfaces_target_arch_on_386_fixture() {
    let Some(analysis): Option<GoAnalysis> = analyze_fixture(common::HELLO_386) else {
        return;
    };
    let bi: &GoBuildInfo = analysis
        .moduledata
        .build_info
        .as_ref()
        .expect("386 fixture carries an embedded build-info blob");
    assert_eq!(
        bi.goarch(),
        Some("386"),
        "the 32-bit fixture must report GOARCH=386 from build settings"
    );
    if let Some(oracle) = oracle_via_toolchain(common::HELLO_386) {
        assert_eq!(recovered_as_oracle(bi).settings, oracle.settings);
    }
}

#[test]
fn buildversion_prefers_authoritative_build_info_go_version() {
    let Some(analysis): Option<GoAnalysis> = analyze_fixture(common::HELLO_NORMAL) else {
        return;
    };
    let bi_version: Option<String> = analysis
        .moduledata
        .build_info
        .as_ref()
        .and_then(|b: &GoBuildInfo| b.go_version.clone());
    assert!(
        bi_version.is_some(),
        "the normal fixture's build-info blob must carry the go toolchain version"
    );
    assert_eq!(
        analysis.buildversion, bi_version,
        "GoAnalysis.buildversion must prefer the authoritative build-info go version"
    );
    assert!(
        analysis
            .buildversion
            .as_deref()
            .is_some_and(|v: &str| v.starts_with("go1.")),
        "expected a go1.x toolchain version, got {:?}",
        analysis.buildversion
    );
}
