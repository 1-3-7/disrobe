#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::process::Command;

use disrobe_pass_go::{GoAnalysis, GoBuildInfo, GoModule, analyze};
use object::{Object, ObjectSection};

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

const BUILDINFO_MARKER: &[u8] = b"\xff Go buildinf:";
const BUILDINFO_HEADER_LEN: usize = 32;
const GO_STRING_HEADER_LEN: usize = 16;
const BUILDINFO_DECOY_LEN: usize = BUILDINFO_HEADER_LEN + 2 * GO_STRING_HEADER_LEN;
const BUILDINFO_ALIGNMENT: u64 = 16;

fn read_uvarint(bytes: &[u8], start: usize) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    for shift in 0..10usize {
        let index: usize = start.checked_add(shift)?;
        let byte: u8 = *bytes.get(index)?;
        value |= u64::from(byte & 0x7f).checked_shl(u32::try_from(shift.checked_mul(7)?).ok()?)?;
        if byte & 0x80 == 0 {
            return Some((value, shift + 1));
        }
    }
    None
}

fn mutate_buildinfo_to_same_section_fallback(bytes: &mut [u8]) -> bool {
    let file: object::File<'_> = match object::File::parse(&*bytes) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let mut placement: Option<(usize, u64, usize, usize, u64)> = None;
    for section in file.sections() {
        let Ok(data): Result<&[u8], object::Error> = section.data() else {
            continue;
        };
        let Some((section_file_start, section_file_len)): Option<(u64, u64)> = section.file_range()
        else {
            continue;
        };
        let Ok(section_file_len): Result<usize, _> = usize::try_from(section_file_len) else {
            continue;
        };
        let Some(file_data): Option<&[u8]> = data.get(..section_file_len) else {
            continue;
        };
        let Some(real_relative): Option<usize> = file_data
            .windows(BUILDINFO_MARKER.len())
            .position(|window: &[u8]| window == BUILDINFO_MARKER)
        else {
            continue;
        };
        let Ok(real_relative_u64): Result<u64, _> = u64::try_from(real_relative) else {
            continue;
        };
        let Some(real_file_u64): Option<u64> = section_file_start.checked_add(real_relative_u64)
        else {
            continue;
        };
        let Ok(real_file): Result<usize, _> = usize::try_from(real_file_u64) else {
            continue;
        };
        let Ok(section_file_start): Result<usize, _> = usize::try_from(section_file_start) else {
            continue;
        };
        let Some(real_va): Option<u64> = section.address().checked_add(real_relative_u64) else {
            continue;
        };
        placement = Some((
            real_file,
            real_va,
            section_file_start,
            section_file_len,
            section.address(),
        ));
        break;
    }
    drop(file);
    let Some((real_file, real_va, section_file_start, section_file_len, section_va)) = placement
    else {
        return false;
    };
    let Some(header): Option<&[u8]> = bytes.get(real_file..real_file + BUILDINFO_HEADER_LEN) else {
        return false;
    };
    if header.get(14) != Some(&8) || header.get(15).is_none_or(|flags: &u8| flags & 0x2 == 0) {
        return false;
    }
    let version_start: usize = real_file + BUILDINFO_HEADER_LEN;
    let Some((version_len, version_prefix)): Option<(u64, usize)> =
        read_uvarint(bytes, version_start)
    else {
        return false;
    };
    let Some(version_data_file): Option<usize> = version_start.checked_add(version_prefix) else {
        return false;
    };
    let Ok(version_len_usize): Result<usize, _> = usize::try_from(version_len) else {
        return false;
    };
    let Some(version_end): Option<usize> = version_data_file.checked_add(version_len_usize) else {
        return false;
    };
    if bytes.get(version_data_file..version_end).is_none() {
        return false;
    }
    let module_start: usize = version_end;
    let Some((module_len, module_prefix)): Option<(u64, usize)> = read_uvarint(bytes, module_start)
    else {
        return false;
    };
    let Some(module_data_file): Option<usize> = module_start.checked_add(module_prefix) else {
        return false;
    };
    let Ok(module_len_usize): Result<usize, _> = usize::try_from(module_len) else {
        return false;
    };
    let Some(module_end): Option<usize> = module_data_file.checked_add(module_len_usize) else {
        return false;
    };
    if bytes.get(module_data_file..module_end).is_none() {
        return false;
    }
    let Some(section_file_end): Option<usize> = section_file_start.checked_add(section_file_len)
    else {
        return false;
    };
    if module_end > section_file_end {
        return false;
    }
    let Some(module_end_relative): Option<usize> = module_end.checked_sub(section_file_start)
    else {
        return false;
    };
    let Some((decoy_relative, decoy_va)): Option<(usize, u64)> = bytes
        .get(section_file_start..section_file_end)
        .and_then(|file_data: &[u8]| {
            file_data
                .get(module_end_relative..)
                .and_then(|tail: &[u8]| {
                    tail.windows(BUILDINFO_DECOY_LEN).enumerate().find_map(
                        |(offset, window): (usize, &[u8])| {
                            if window.iter().any(|byte: &u8| *byte != 0) {
                                return None;
                            }
                            let relative: usize = module_end_relative.checked_add(offset)?;
                            let va: u64 = section_va.checked_add(u64::try_from(relative).ok()?)?;
                            va.is_multiple_of(BUILDINFO_ALIGNMENT)
                                .then_some((relative, va))
                        },
                    )
                })
        })
    else {
        return false;
    };
    let Some(decoy_file): Option<usize> = section_file_start.checked_add(decoy_relative) else {
        return false;
    };
    let Some(version_relative): Option<usize> = BUILDINFO_HEADER_LEN.checked_add(version_prefix)
    else {
        return false;
    };
    let Ok(version_relative_u64): Result<u64, _> = u64::try_from(version_relative) else {
        return false;
    };
    let Some(module_relative): Option<usize> = module_data_file.checked_sub(real_file) else {
        return false;
    };
    let Ok(module_relative_u64): Result<u64, _> = u64::try_from(module_relative) else {
        return false;
    };
    let Some(version_data_va): Option<u64> = real_va.checked_add(version_relative_u64) else {
        return false;
    };
    let Some(module_data_va): Option<u64> = real_va.checked_add(module_relative_u64) else {
        return false;
    };
    let Some(version_header_va): Option<u64> = decoy_va.checked_add(BUILDINFO_HEADER_LEN as u64)
    else {
        return false;
    };
    let Some(module_header_va): Option<u64> =
        version_header_va.checked_add(GO_STRING_HEADER_LEN as u64)
    else {
        return false;
    };
    let Some(original_header): Option<&mut [u8]> =
        bytes.get_mut(real_file..real_file + BUILDINFO_HEADER_LEN)
    else {
        return false;
    };
    original_header[14] = 0;
    original_header[15] = 0;
    let Some(decoy): Option<&mut [u8]> =
        bytes.get_mut(decoy_file..decoy_file + BUILDINFO_DECOY_LEN)
    else {
        return false;
    };
    decoy[..BUILDINFO_MARKER.len()].copy_from_slice(BUILDINFO_MARKER);
    decoy[14] = 8;
    decoy[16..24].copy_from_slice(&version_header_va.to_le_bytes());
    decoy[24..32].copy_from_slice(&module_header_va.to_le_bytes());
    decoy[32..40].copy_from_slice(&version_data_va.to_le_bytes());
    decoy[40..48].copy_from_slice(&version_len.to_le_bytes());
    decoy[48..56].copy_from_slice(&module_data_va.to_le_bytes());
    decoy[56..64].copy_from_slice(&module_len.to_le_bytes());
    true
}

#[test]
fn buildinfo_skips_malformed_marker_before_same_section_fallback() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("buildinfo_decoy");
    common::write_module(&scratch, "disrobe.example/buildinfodecoy", BUILDINFO_SOURCE);
    let Some(binary): Option<std::path::PathBuf> =
        common::go_build(&scratch, "buildinfo_decoy.exe", &[])
    else {
        panic!("go build failed; the real-toolchain reference cannot run");
    };
    let reference: common::GoVersionM =
        common::go_version_m(&binary).expect("go version -m must read the fresh binary");
    let mut bytes: Vec<u8> = std::fs::read(&binary).expect("read fresh Go binary");
    assert!(
        mutate_buildinfo_to_same_section_fallback(&mut bytes),
        "the Go toolchain binary must provide room for a same-section fallback record"
    );

    let analysis: GoAnalysis = analyze(&bytes).expect("analyze binary with malformed predecessor");
    let build_info: &GoBuildInfo = analysis
        .moduledata
        .build_info
        .as_ref()
        .expect("a malformed predecessor must not hide the valid build-info record");
    assert_eq!(build_info.path, reference.path);
    assert_eq!(build_info.go_version, reference.go_version);
    assert_eq!(build_info.settings, reference.settings);
}

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

#[derive(Clone, Copy)]
struct MatrixTarget {
    goarch: &'static str,
    stripped: bool,
}

const MATRIX_MODULE: &str = "disrobe.example/buildinfomatrix";

const MATRIX: [MatrixTarget; 4] = [
    MatrixTarget {
        goarch: "amd64",
        stripped: false,
    },
    MatrixTarget {
        goarch: "amd64",
        stripped: true,
    },
    MatrixTarget {
        goarch: "386",
        stripped: false,
    },
    MatrixTarget {
        goarch: "386",
        stripped: true,
    },
];

#[test]
fn buildinfo_matches_oracle_across_arch_and_strip_matrix() {
    if !common::require_go() {
        return;
    }
    let scratch: common::GoBuildScratch = common::new_scratch("buildinfo_matrix");
    common::write_module(&scratch, MATRIX_MODULE, BUILDINFO_SOURCE);

    let mut built: usize = 0;
    for target in MATRIX {
        let out_name: String = format!(
            "matrix_{}_{}.exe",
            target.goarch,
            if target.stripped { "stripped" } else { "full" }
        );
        let extra: &[&str] = if target.stripped {
            &["-ldflags", "-s -w"]
        } else {
            &[]
        };
        let Some(binary): Option<std::path::PathBuf> =
            common::go_build_cross(&scratch, &out_name, "windows", target.goarch, extra)
        else {
            eprintln!(
                "SKIP matrix target windows/{} stripped={}: go build failed on this host",
                target.goarch, target.stripped
            );
            continue;
        };
        built += 1;

        let oracle: common::GoVersionM = common::go_version_m(&binary)
            .expect("go version -m must produce the build-info reference for a matrix target");

        let bytes: Vec<u8> = std::fs::read(&binary).expect("read matrix build");
        let analysis: GoAnalysis = analyze(&bytes).expect("analyze matrix build");
        let bi: &GoBuildInfo = analysis.moduledata.build_info.as_ref().unwrap_or_else(|| {
            panic!(
                "build-info blob must survive windows/{} stripped={}",
                target.goarch, target.stripped
            )
        });

        assert_eq!(
            bi.path.as_deref(),
            Some(MATRIX_MODULE),
            "recovered module path must equal the go.mod module for windows/{} stripped={}",
            target.goarch,
            target.stripped
        );
        assert_eq!(
            bi.path.as_deref(),
            oracle.path.as_deref(),
            "recovered module path must match `go version -m` for windows/{} stripped={}",
            target.goarch,
            target.stripped
        );
        assert_eq!(
            bi.go_version, oracle.go_version,
            "recovered go toolchain version must match `go version -m` for windows/{} stripped={}",
            target.goarch, target.stripped
        );
        assert_eq!(
            bi.settings, oracle.settings,
            "recovered build settings must match `go version -m` exactly for windows/{} stripped={}",
            target.goarch, target.stripped
        );
        assert_eq!(
            bi.goos(),
            Some("windows"),
            "GOOS must surface for windows/{} stripped={}",
            target.goarch,
            target.stripped
        );
        assert_eq!(
            bi.goarch(),
            Some(target.goarch),
            "GOARCH must surface for windows/{} stripped={}",
            target.goarch,
            target.stripped
        );
        assert_eq!(
            analysis.buildversion, oracle.go_version,
            "buildversion must prefer the build-info go version for windows/{} stripped={}",
            target.goarch, target.stripped
        );
    }

    assert!(
        built > 0,
        "no matrix target built on this host; the reference could not run"
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
