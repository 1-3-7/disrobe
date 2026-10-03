#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_lua::hercules;
use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};

const FIXTURES: [(&str, &str); 15] = [
    ("branches", "balanced"),
    ("branches", "heavy"),
    ("branches", "light"),
    ("branches", "maximum"),
    ("loops", "balanced"),
    ("loops", "light"),
    ("objects", "balanced"),
    ("objects", "heavy"),
    ("objects", "light"),
    ("objects", "maximum"),
    ("tour", "balanced"),
    ("tour", "light"),
    ("values", "balanced"),
    ("values", "heavy"),
    ("values", "light"),
];

const FULLY_RECOVERED: [&str; 14] = [
    "branches.balanced",
    "branches.heavy",
    "branches.light",
    "loops.balanced",
    "loops.light",
    "objects.balanced",
    "objects.heavy",
    "objects.light",
    "objects.maximum",
    "tour.balanced",
    "tour.light",
    "values.balanced",
    "values.heavy",
    "values.light",
];

const PARTIAL: [(&str, &str); 1] = [("branches.maximum", "VMGenerator")];

const LAYER_RESIDUE: [&str; 9] = [
    "Obfuscated by Hercules",
    "Tamper Detected",
    "thing==thing2",
    "thing == thing2",
    "counter<1",
    "math.ldexp",
    "loadstring",
    ":byte(i)",
    "end)()",
];

const PRINTED_LITERALS: [(&str, &str); 5] = [
    ("branches", ","),
    ("loops", "numeric"),
    ("objects", " says "),
    ("tour", "Hello World"),
    ("values", "outer else"),
];

const RUN_TIMEOUT: Duration = Duration::from_secs(10);

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

fn corpus_lua() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../corpus/lua")
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|err: std::io::Error| {
        panic!(
            "a graded Hercules fixture or reference is missing at {}: {err}",
            path.display()
        )
    })
}

fn lua54() -> String {
    let mut seen: Vec<String> = Vec::new();
    for program in ["lua5.4", "lua54", "lua"] {
        match Command::new(program).arg("-v").output() {
            Ok(output) => {
                let banner: String = format!(
                    "{}{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                if banner.contains("Lua 5.4") {
                    return program.to_owned();
                }
                seen.push(format!("`{program}` reports `{}`", banner.trim()));
            }
            Err(err) => seen.push(format!("`{program}`: {err}")),
        }
    }
    panic!(
        "the Hercules real-output grader runs the original program and the recovered source under \
         lua5.4 and cannot grade without it: {}. Install lua5.4 (apt-get install lua5.4) or put its \
         bin directory on PATH",
        seen.join("; ")
    )
}

fn run(lua: &str, dir: &Path, name: &str, source: &[u8]) -> Result<String, String> {
    let script: PathBuf = dir.join(format!("{name}.lua"));
    std::fs::write(&script, source).map_err(|err: std::io::Error| err.to_string())?;
    let out_path: PathBuf = dir.join(format!("{name}.stdout"));
    let err_path: PathBuf = dir.join(format!("{name}.stderr"));
    let stdout: File = File::create(&out_path).map_err(|err: std::io::Error| err.to_string())?;
    let stderr: File = File::create(&err_path).map_err(|err: std::io::Error| err.to_string())?;
    let mut child: std::process::Child = Command::new(lua)
        .arg(&script)
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .map_err(|err: std::io::Error| format!("`{lua}` failed to launch: {err}"))?;
    let deadline: Instant = Instant::now() + RUN_TIMEOUT;
    let status: std::process::ExitStatus = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err: std::io::Error| err.to_string())?
        {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{name} ran past {RUN_TIMEOUT:?}"));
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let printed: String = std::fs::read_to_string(&out_path)
        .map_err(|err: std::io::Error| err.to_string())?
        .replace("\r\n", "\n");
    if status.success() {
        Ok(printed)
    } else {
        Err(format!(
            "{name} exited {status}: {}",
            std::fs::read_to_string(&err_path).unwrap_or_default()
        ))
    }
}

fn scratch() -> ScratchDir {
    let seq: u64 = SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    ScratchDir::create(&format!("hercules_real-{}-{seq}", std::process::id()))
        .expect("scratch dir for the Hercules grader")
}

fn printed_literal(program: &str) -> &'static str {
    PRINTED_LITERALS
        .iter()
        .find(|(name, _): &&(&str, &str)| *name == program)
        .map_or_else(
            || panic!("{program} has no printed literal for the mutation control"),
            |(_, literal): &(&str, &str)| *literal,
        )
}

fn mutate_literal(source: &str, literal: &str) -> String {
    let quoted: String = format!("\"{literal}\"");
    let at: usize = source.find(&quoted).unwrap_or_else(|| {
        panic!(
            "the recovered source must carry the decoded literal {quoted} for the mutation control"
        )
    });
    let first: char = literal.chars().next().expect("non-empty literal");
    let swapped: char = if first == 'X' { 'Y' } else { 'X' };
    let mut mutated: String = source.to_owned();
    mutated.replace_range(at + 1..at + 1 + first.len_utf8(), &swapped.to_string());
    mutated
}

#[derive(Debug)]
struct Graded {
    fixture: String,
    fully_recovered: bool,
}

fn grade(lua: &str, dir: &Path, program: &str, preset: &str) -> Graded {
    let fixture: String = format!("{program}.{preset}");
    let obfuscated: Vec<u8> = read(&corpus_lua().join(format!("hercules/real/{fixture}.lua")));
    let obfuscated_text: String = String::from_utf8_lossy(&obfuscated).into_owned();
    assert!(
        obfuscated_text.contains("--[Obfuscated by Hercules v2.0.0"),
        "{fixture} is graded as real Hercules output, so it must carry the tool's watermark"
    );
    let peeled: PeelResult = hercules::peel(&obfuscated, &DeobfOptions::default())
        .unwrap_or_else(|err: disrobe_pass_lua::Error| panic!("{fixture}: peel failed: {err}"));
    let recovered: String = String::from_utf8(peeled.deobfuscated.clone()).unwrap_or_else(
        |err: std::string::FromUtf8Error| panic!("{fixture}: recovered source is not UTF-8: {err}"),
    );

    if !peeled.fully_recovered {
        let (_, layer): &(&str, &str) = PARTIAL
            .iter()
            .find(|(name, _): &&(&str, &str)| *name == fixture)
            .unwrap_or_else(|| {
                panic!(
                    "{fixture} is not fully recovered and is not listed as a named partial; \
                     residual markers: {:?}",
                    peeled.residual_markers
                )
            });
        assert!(
            peeled
                .residual_markers
                .iter()
                .any(|marker: &String| marker.contains(layer)),
            "{fixture} must name the {layer} layer it leaves behind, got {:?}",
            peeled.residual_markers
        );
        return Graded {
            fixture,
            fully_recovered: false,
        };
    }

    assert!(
        peeled.residual_markers.is_empty(),
        "{fixture}: a full recovery reports no residual layer, got {:?}",
        peeled.residual_markers
    );
    for residue in LAYER_RESIDUE {
        assert!(
            !recovered.contains(residue),
            "{fixture}: recovered source still carries the Hercules layer text `{residue}`:\n{recovered}"
        );
    }

    let original: Vec<u8> = read(&corpus_lua().join(format!("behaviour/{program}.lua")));
    let expected: String = run(lua, dir, &format!("{fixture}.original"), &original)
        .unwrap_or_else(|err: String| panic!("{fixture}: the original program must run: {err}"));
    assert!(
        !expected.is_empty(),
        "{fixture}: the original program printed nothing, so the comparison would be vacuous"
    );
    let actual: String = run(
        lua,
        dir,
        &format!("{fixture}.recovered"),
        recovered.as_bytes(),
    )
    .unwrap_or_else(|err: String| {
        panic!("{fixture}: the recovered source must run: {err}\n{recovered}")
    });
    assert_eq!(
        actual, expected,
        "{fixture}: the recovered source prints differently from the original program\n{recovered}"
    );

    let mutated: String = mutate_literal(&recovered, printed_literal(program));
    let mutated_run: Result<String, String> =
        run(lua, dir, &format!("{fixture}.mutated"), mutated.as_bytes());
    assert_ne!(
        mutated_run.as_ref().ok(),
        Some(&expected),
        "{fixture}: a one-token change to the recovered source still matched the original output, \
         so this comparison cannot fail"
    );

    Graded {
        fixture,
        fully_recovered: true,
    }
}

#[test]
fn real_hercules_output_recovers_to_programs_that_print_like_the_originals() {
    let lua: String = lua54();
    let dir: ScratchDir = scratch();
    let mut recovered: BTreeSet<String> = BTreeSet::new();
    let mut partial: BTreeSet<String> = BTreeSet::new();
    for (program, preset) in FIXTURES {
        let graded: Graded = grade(&lua, dir.path(), program, preset);
        if graded.fully_recovered {
            recovered.insert(graded.fixture);
        } else {
            partial.insert(graded.fixture);
        }
    }
    let pinned: BTreeSet<String> = FULLY_RECOVERED
        .iter()
        .map(|name: &&str| (*name).to_owned())
        .collect();
    assert_eq!(
        recovered, pinned,
        "the set of fully recovered real Hercules fixtures moved; a fixture leaving it is a \
         regression, and one joining it must be added to FULLY_RECOVERED"
    );
    let named: BTreeSet<String> = PARTIAL
        .iter()
        .map(|(name, _): &(&str, &str)| (*name).to_owned())
        .collect();
    assert_eq!(
        partial, named,
        "every fixture short of full recovery must be a named partial"
    );
    assert_eq!(recovered.len() + partial.len(), FIXTURES.len());
}

#[test]
fn every_committed_real_fixture_is_graded() {
    let dir: PathBuf = corpus_lua().join("hercules/real");
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err: std::io::Error| panic!("cannot list {}: {err}", dir.display()))
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    on_disk.sort();
    let mut graded: Vec<String> = FIXTURES
        .iter()
        .map(|(program, preset): &(&str, &str)| format!("{program}.{preset}.lua"))
        .collect();
    graded.sort();
    assert_eq!(
        on_disk, graded,
        "a real Hercules fixture landed or left without this grader following it"
    );
}

#[test]
fn originals_do_not_carry_the_layer_residue_the_grader_rejects() {
    for (program, _) in PRINTED_LITERALS {
        let original: String =
            String::from_utf8(read(&corpus_lua().join(format!("behaviour/{program}.lua"))))
                .expect("utf8 original");
        for residue in LAYER_RESIDUE {
            assert!(
                !original.contains(residue),
                "behaviour/{program}.lua itself contains `{residue}`, so rejecting it in a recovery \
                 would penalise a faithful result"
            );
        }
        assert!(
            original.contains(&format!("\"{}\"", printed_literal(program))),
            "behaviour/{program}.lua must print the mutation-control literal"
        );
    }
}
