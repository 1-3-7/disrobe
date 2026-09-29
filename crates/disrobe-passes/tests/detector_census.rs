#![allow(
    clippy::expect_used,
    clippy::panic,
    reason = "the census is a gate over committed corpus bytes and must fail loudly when it cannot run"
)]

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use disrobe_core::chain::{
    ConfidenceBand, DetectContext, DetectVerdict, DetectorPick, FAMILY_OBFUSCATOR_WRAPPER,
    FAMILY_PACKER_ARCHIVE, PassRegistry, SelectionPolicy, compare,
};
use disrobe_passes::build_registry;

const CENSUS: &str = "crates/disrobe-passes/tests/data/detector_census.tsv";
const WRITE_ENV: &str = "DISROBE_WRITE_DETECTOR_CENSUS";
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
const HEADER: &str =
    "path\tpass\tformat_tag\tfamily\tband\trunner_up_pass\trunner_up_family\trunner_up_band";
const ABSENT: &str = "-";

struct Verdict {
    pass: String,
    format_tag: String,
    family: String,
    band: ConfidenceBand,
}

struct CensusRow {
    path: String,
    chosen: Option<Verdict>,
    runner_up: Option<Verdict>,
    claims: Vec<Verdict>,
}

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn tracked_corpus(root: &Path) -> Vec<String> {
    let output: Output = Command::new("git")
        .args(["ls-files", "-z", "--", "corpus"])
        .current_dir(root)
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("git ls-files is required to list the tracked corpus: {error}")
        });
    assert!(
        output.status.success(),
        "git ls-files failed in {}: {}",
        root.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let raw: String =
        String::from_utf8(output.stdout).unwrap_or_else(|error: std::string::FromUtf8Error| {
            panic!("git ls-files returned a non-UTF-8 path: {error}")
        });
    let mut paths: Vec<String> = raw
        .split('\0')
        .filter(|entry: &&str| !entry.is_empty())
        .map(|entry: &str| entry.replace('\\', "/"))
        .collect();
    paths.sort();
    assert!(
        paths.len() > 1000,
        "git ls-files listed only {} corpus files, so the tracked corpus is not established",
        paths.len()
    );
    paths
}

fn is_corpus_prose(path: &str) -> bool {
    let name: &str = path.rsplit('/').next().unwrap_or(path);
    let (stem, extension): (&str, &str) = name.split_once('.').unwrap_or((name, ""));
    let prose_stem: bool = ["MANIFEST", "BUILD", "README"]
        .iter()
        .any(|expected: &&str| stem.eq_ignore_ascii_case(expected));
    let prose_extension: bool = ["", "toml", "md", "txt", "tsv", "json"]
        .iter()
        .any(|expected: &&str| extension.eq_ignore_ascii_case(expected));
    prose_stem && prose_extension
}

const fn band_name(band: ConfidenceBand) -> &'static str {
    match band {
        ConfidenceBand::Low => "low",
        ConfidenceBand::Medium => "medium",
        ConfidenceBand::High => "high",
    }
}

fn verdict_of(verdict: &DetectVerdict) -> Verdict {
    Verdict {
        pass: verdict.pass_id.to_owned(),
        format_tag: verdict.format_tag.to_owned(),
        family: verdict.family.to_owned(),
        band: verdict.band,
    }
}

fn census_row(registry: &PassRegistry, root: &Path, path: &str) -> Option<CensusRow> {
    if is_corpus_prose(path) {
        return None;
    }
    let absolute: PathBuf = root.join(path);
    let size: u64 = std::fs::metadata(&absolute)
        .unwrap_or_else(|error: std::io::Error| {
            panic!("tracked corpus file {path} is missing from the checkout: {error}")
        })
        .len();
    if size > MAX_INPUT_BYTES {
        return None;
    }
    let bytes: Vec<u8> = std::fs::read(&absolute).unwrap_or_else(|error: std::io::Error| {
        panic!("tracked corpus file {path} is unreadable: {error}")
    });
    let ctx: DetectContext<'_> = DetectContext {
        bytes: &bytes,
        path_hint: Some(path),
        parent_hint: None,
        depth: 1,
    };
    let mut candidates: Vec<DetectVerdict> = registry.run_all(&ctx);
    candidates.sort_by(|a: &DetectVerdict, b: &DetectVerdict| compare(a, b).reverse());
    let policy: SelectionPolicy = SelectionPolicy::default();
    let claims: Vec<Verdict> = candidates
        .iter()
        .filter(|v: &&DetectVerdict| v.confidence >= policy.min_confidence)
        .map(verdict_of)
        .collect();
    let chosen: Option<Verdict> = registry
        .pick(candidates.clone())
        .map(|p: DetectorPick| verdict_of(&p.verdict));
    let runner_up: Option<Verdict> = candidates
        .get(usize::from(chosen.is_some()))
        .map(verdict_of);
    Some(CensusRow {
        path: path.to_owned(),
        chosen,
        runner_up,
        claims,
    })
}

fn census() -> &'static [CensusRow] {
    static CENSUS_ROWS: OnceLock<Vec<CensusRow>> = OnceLock::new();
    CENSUS_ROWS.get_or_init(|| {
        let root: PathBuf = workspace_root();
        let registry: PassRegistry = build_registry();
        tracked_corpus(&root)
            .iter()
            .filter_map(|path: &String| census_row(&registry, &root, path))
            .collect()
    })
}

fn mask_serial_digits(path: &str) -> String {
    const SERIAL_DIGITS: usize = 6;
    let mut masked: String = String::with_capacity(path.len());
    let mut run: String = String::new();
    for c in path.chars().chain(std::iter::once('/')) {
        if c.is_ascii_digit() {
            run.push(c);
            continue;
        }
        if run.len() == SERIAL_DIGITS {
            masked.push_str("<serial>");
        } else {
            masked.push_str(&run);
        }
        run.clear();
        masked.push(c);
    }
    masked.pop();
    masked
}

fn render(rows: &[CensusRow]) -> String {
    let mut out: String = String::with_capacity(rows.len() * 128);
    out.push_str(HEADER);
    out.push('\n');
    for row in rows {
        let (pass, format_tag, family, band): (&str, &str, &str, &str) = row
            .chosen
            .as_ref()
            .map_or((ABSENT, ABSENT, ABSENT, ABSENT), |v: &Verdict| {
                (&v.pass, &v.format_tag, &v.family, band_name(v.band))
            });
        let (runner_pass, runner_family, runner_band): (&str, &str, &str) = row
            .runner_up
            .as_ref()
            .map_or((ABSENT, ABSENT, ABSENT), |v: &Verdict| {
                (&v.pass, &v.family, band_name(v.band))
            });
        writeln!(
            out,
            "{}\t{pass}\t{format_tag}\t{family}\t{band}\t{runner_pass}\t{runner_family}\t{runner_band}",
            mask_serial_digits(&row.path)
        )
        .expect("writing to a String cannot fail");
    }
    out
}

#[test]
fn the_committed_detector_census_matches_every_tracked_corpus_verdict() {
    let rendered: String = render(census());
    let path: PathBuf = workspace_root().join(CENSUS);
    if std::env::var_os(WRITE_ENV).is_some() {
        std::fs::create_dir_all(path.parent().expect("census parent"))
            .expect("create the census directory");
        std::fs::write(&path, rendered.as_bytes()).expect("write the detector census");
        return;
    }
    let committed: String =
        std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
            panic!(
                "{CENSUS} is unreadable ({error}); run this test with {WRITE_ENV}=1 to record it"
            )
        });
    let committed: String = committed.replace("\r\n", "\n");
    if committed == rendered {
        return;
    }
    let old: BTreeSet<&str> = committed.lines().collect();
    let new: BTreeSet<&str> = rendered.lines().collect();
    let removed: Vec<&&str> = old.difference(&new).collect();
    let added: Vec<&&str> = new.difference(&old).collect();
    let mut diff: String = String::new();
    for line in removed.iter().take(40) {
        writeln!(diff, "- {line}").expect("writing to a String cannot fail");
    }
    for line in added.iter().take(40) {
        writeln!(diff, "+ {line}").expect("writing to a String cannot fail");
    }
    panic!(
        "the detector census drifted from {CENSUS} ({} rows removed, {} added); review each \
         changed verdict, then rerun with {WRITE_ENV}=1 to record it:\n{diff}",
        removed.len(),
        added.len()
    );
}

struct Selection {
    manifest: &'static str,
    selects: fn(&str) -> bool,
}

fn under(path: &str, prefixes: &[&str]) -> bool {
    prefixes
        .iter()
        .any(|prefix: &&str| path.starts_with(prefix))
}

fn one_of(path: &str, paths: &[&str]) -> bool {
    paths.contains(&path)
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

const UNOBFUSCATED: [Selection; 27] = [
    Selection {
        manifest: "corpus/src/_edge_cases_meta/README.md",
        selects: |p: &str| p.starts_with("corpus/src/") && p.contains("/edge_cases/"),
    },
    Selection {
        manifest: "corpus/native/anti-analysis/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/native/anti-analysis/"]),
    },
    Selection {
        manifest: "corpus/native/compilers/go/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/native/compilers/go/"]),
    },
    Selection {
        manifest: "corpus/native/formats/PROVENANCE.txt",
        selects: |p: &str| {
            under(
                p,
                &[
                    "corpus/native/formats/",
                    "corpus/native/arch/",
                    "corpus/native/linkers/",
                    "corpus/native/nim/",
                    "corpus/native/zig/",
                ],
            )
        },
    },
    Selection {
        manifest: "corpus/native/obfuscators/obfush/MANIFEST.toml",
        selects: |p: &str| {
            p.starts_with("corpus/native/obfuscators/") && name_of(p).starts_with("sample.clean.")
        },
    },
    Selection {
        manifest: "corpus/native/packers/MANIFEST.toml",
        selects: |p: &str| p.starts_with("corpus/native/packers/") && p.ends_with(".original.exe"),
    },
    Selection {
        manifest: "corpus/dotnet/MANIFEST.toml",
        selects: |p: &str| {
            one_of(
                p,
                &[
                    "corpus/dotnet/HelloApp.dll",
                    "corpus/dotnet/HelloApp.r2r.exe",
                    "corpus/dotnet/HelloApp.r2r.dll",
                    "corpus/dotnet/HelloAppAot.exe",
                    "corpus/dotnet/HelloAppAot.dll",
                    "corpus/dotnet/HelloAppLegacy.dll",
                    "corpus/dotnet/megafile/EdgeCases.baseline.dll",
                    "corpus/dotnet/megafile/EdgeCases.r2r.dll",
                    "corpus/dotnet/megafile/EdgeCases.nativeaot.exe",
                    "corpus/dotnet/megafile/EdgeCases.cs",
                    "corpus/dotnet/megafile/EdgeCasesMore.cs",
                    "corpus/dotnet/megafile/Polyfills.cs",
                    "corpus/dotnet/cil/CilProbe.dll",
                    "corpus/dotnet/cil/Probe.cs",
                    "corpus/dotnet/patterns/Patterns.dll",
                    "corpus/dotnet/proppat/PropMatch.dll",
                    "corpus/dotnet/typerel/TypeRel.dll",
                    "corpus/dotnet/branches/Branches.dll",
                ],
            )
        },
    },
    Selection {
        manifest: "corpus/jvm/MANIFEST.toml",
        selects: |p: &str| {
            under(p, &["corpus/jvm/megafile/"])
                || one_of(
                    p,
                    &[
                        "corpus/jvm/proguard/Hello-baseline.jar",
                        "corpus/jvm/proguard/Hello-baseline.class",
                        "corpus/jvm/dex/Hello.dex",
                        "corpus/jvm/dex/EdgeCases.dex",
                        "corpus/jvm/dex/EdgeCasesKt.dex",
                    ],
                )
        },
    },
    Selection {
        manifest: "corpus/jvm/kotlin/MANIFEST.txt",
        selects: |p: &str| under(p, &["corpus/jvm/kotlin/", "corpus/jvm/groovy/"]),
    },
    Selection {
        manifest: "corpus/lua/MANIFEST.toml",
        selects: |p: &str| {
            under(
                p,
                &[
                    "corpus/lua/baseline/",
                    "corpus/lua/megafile/",
                    "corpus/lua/luac/",
                    "corpus/lua/luajit/",
                    "corpus/lua/luau/",
                ],
            )
        },
    },
    Selection {
        manifest: "corpus/lua/decompile_samples/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/lua/decompile_samples/"]),
    },
    Selection {
        manifest: "corpus/lua/ironbrew2/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/lua/ironbrew2/original/"]),
    },
    Selection {
        manifest: "corpus/php/MANIFEST.toml",
        selects: |p: &str| {
            under(
                p,
                &[
                    "corpus/php/baseline/",
                    "corpus/php/megafile/",
                    "corpus/php/oparray/src/",
                ],
            ) || one_of(
                p,
                &[
                    "corpus/php/yakpro/calc_original.php",
                    "corpus/php/yakpro/controlflow_original.php",
                ],
            )
        },
    },
    Selection {
        manifest: "corpus/python/decompile/authored/BUILD.md",
        selects: |p: &str| under(p, &["corpus/python/decompile/"]),
    },
    Selection {
        manifest: "corpus/python/alt_runtimes/pypy/PROVENANCE.txt",
        selects: |p: &str| under(p, &["corpus/python/alt_runtimes/"]),
    },
    Selection {
        manifest: "corpus/ruby/MANIFEST.toml",
        selects: |p: &str| {
            under(
                p,
                &[
                    "corpus/ruby/behaviour/",
                    "corpus/ruby/megafile/",
                    "corpus/ruby/mri/",
                    "corpus/ruby/mruby/",
                ],
            ) || one_of(p, &["corpus/ruby/hello.rb", "corpus/ruby/greeter.rb"])
        },
    },
    Selection {
        manifest: "corpus/beam/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/beam/"]),
    },
    Selection {
        manifest: "corpus/r/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/r/"]),
    },
    Selection {
        manifest: "corpus/pickle/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/pickle/"]),
    },
    Selection {
        manifest: "corpus/flash/swf/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/flash/"]),
    },
    Selection {
        manifest: "corpus/wasm/obf/MANIFEST.md",
        selects: |p: &str| {
            p.starts_with("corpus/wasm/obf/")
                && (p.ends_with(".clean.wat") || p.ends_with(".clean.c"))
        },
    },
    Selection {
        manifest: "corpus/mobile/hermes/MANIFEST.toml",
        selects: |p: &str| under(p, &["corpus/mobile/hermes/"]),
    },
    Selection {
        manifest: "corpus/shell/MANIFEST.toml",
        selects: |p: &str| {
            under(
                p,
                &[
                    "corpus/shell/bash/megafile/",
                    "corpus/shell/batch/megafile/",
                    "corpus/shell/batch/baseline/",
                    "corpus/shell/powershell/megafile/",
                    "corpus/shell/vba/megafile/",
                ],
            ) || one_of(p, &["corpus/shell/vbs/hello.vbs"])
        },
    },
    Selection {
        manifest: "corpus/js/MANIFEST.toml",
        selects: |p: &str| {
            one_of(p, &["corpus/js/hello.js"])
                || under(p, &["corpus/js/megafile/"])
                || (p.starts_with("corpus/js/")
                    && p.matches('/').count() == 3
                    && matches!(name_of(p), "hello.js" | "edge_cases.js" | "input.js"))
        },
    },
    Selection {
        manifest: "corpus/js/MANIFEST.toml",
        selects: |p: &str| {
            under(
                p,
                &[
                    "corpus/js/terser/",
                    "corpus/js/closure/",
                    "corpus/js/babel-preset-env/",
                    "corpus/js/tsc/",
                    "corpus/js/webpack5/",
                    "corpus/js/rollup/",
                    "corpus/js/vite/",
                    "corpus/js/esbuild/",
                    "corpus/js/bun/",
                    "corpus/js/parcel/",
                    "corpus/js/browserify/",
                    "corpus/js/systemjs/",
                    "corpus/js/requirejs/",
                    "corpus/js/turbopack/",
                ],
            )
        },
    },
    Selection {
        manifest: "corpus/binfmt/MANIFEST.toml",
        selects: |p: &str| {
            p.starts_with("corpus/binfmt/")
                && (p.contains("/expected/") || p.contains("/files_expected/"))
        },
    },
    Selection {
        manifest: "corpus/python/marshal/generate.py",
        selects: |p: &str| under(p, &["corpus/python/marshal/originals/"]),
    },
];

const PENDING_FALSE_CLAIMS: [(&str, &str); 0] = [];

const PROTECTION_WORDS: [&str; 4] = ["obfusc", "protect", "packer", "unpack"];

fn is_protection_claim(verdict: &Verdict) -> bool {
    let named: bool = PROTECTION_WORDS
        .iter()
        .any(|word: &&str| verdict.pass.contains(word) || verdict.format_tag.contains(word));
    named || verdict.family == FAMILY_OBFUSCATOR_WRAPPER || verdict.family == FAMILY_PACKER_ARCHIVE
}

#[test]
fn tracked_unobfuscated_inputs_carry_no_protector_packer_or_obfuscator_claim() {
    let root: PathBuf = workspace_root();
    let rows: &[CensusRow] = census();
    let mut violations: Vec<String> = Vec::new();
    let mut pending_seen: BTreeSet<(&str, &str)> = BTreeSet::new();
    for selection in &UNOBFUSCATED {
        assert!(
            root.join(selection.manifest).is_file(),
            "the selection rule's manifest {} is missing, so the rule is no longer anchored",
            selection.manifest
        );
        let selected: Vec<&CensusRow> = rows
            .iter()
            .filter(|row: &&CensusRow| (selection.selects)(&row.path))
            .collect();
        assert!(
            !selected.is_empty(),
            "the selection rule anchored on {} selects no tracked corpus file",
            selection.manifest
        );
        for row in selected {
            for claim in row
                .claims
                .iter()
                .filter(|v: &&Verdict| is_protection_claim(v))
            {
                let pending: Option<&(&str, &str)> =
                    PENDING_FALSE_CLAIMS
                        .iter()
                        .find(|(pass, tag): &&(&str, &str)| {
                            claim.pass == *pass && claim.format_tag == *tag
                        });
                if let Some(entry) = pending {
                    pending_seen.insert(*entry);
                    continue;
                }
                violations.push(format!(
                    "{} ({}): {} {} {} {}",
                    row.path,
                    selection.manifest,
                    claim.pass,
                    claim.format_tag,
                    claim.family,
                    band_name(claim.band)
                ));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "{} protector, packer or obfuscator claims on unobfuscated inputs:\n{}",
        violations.len(),
        violations.join("\n")
    );
    let resolved: Vec<&(&str, &str)> = PENDING_FALSE_CLAIMS
        .iter()
        .filter(|entry: &&(&str, &str)| !pending_seen.contains(*entry))
        .collect();
    assert!(
        resolved.is_empty(),
        "these pending false claims no longer occur on an unobfuscated input; remove them from \
         PENDING_FALSE_CLAIMS: {resolved:?}"
    );
}
