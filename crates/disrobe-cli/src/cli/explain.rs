#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use serde::Serialize;

use super::output::{OutputFormat, emit};

#[derive(Debug, Serialize)]
struct ExplainResult<'a> {
    code: &'a str,
    title: &'a str,
    description: &'a str,
    common_causes: &'a [&'a str],
    common_fixes: &'a [&'a str],
    crate_path: &'a str,
}

#[derive(Debug)]
pub(crate) struct CodeEntry {
    pub(crate) code: &'static str,
    pub(crate) title: &'static str,
    pub(crate) description: &'static str,
    common_causes: &'static [&'static str],
    common_fixes: &'static [&'static str],
    pub(crate) crate_path: &'static str,
}

pub(crate) fn lookup_for_serve(code: &str) -> Option<&'static CodeEntry> {
    let normalized: String = normalize(code);
    lookup(&normalized)
}

pub(crate) fn run(code: String, fmt: OutputFormat) -> miette::Result<()> {
    let normalized: String = normalize(&code);
    let Some(entry): Option<&'static CodeEntry> = lookup(&normalized) else {
        let unknown_msg: String = format!(
            "no documentation registered for `{normalized}`. please file an issue at https://github.com/1-3-7/disrobe/issues including the full error message you saw."
        );
        if fmt.is_machine() {
            let payload: serde_json::Value = serde_json::json!({
                "code": normalized,
                "known": false,
                "message": unknown_msg,
            });
            return emit(fmt, &payload, || {});
        }
        return Err(miette::miette!("DR-CLI-0102: {unknown_msg}"));
    };

    let result: ExplainResult<'_> = ExplainResult {
        code: entry.code,
        title: entry.title,
        description: entry.description,
        common_causes: entry.common_causes,
        common_fixes: entry.common_fixes,
        crate_path: entry.crate_path,
    };
    emit(fmt, &result, || {
        println!("{}", entry.code);
        println!("  title:       {}", entry.title);
        println!("  description: {}", entry.description);
        println!("  crate:       {}", entry.crate_path);
        if !entry.common_causes.is_empty() {
            println!("  common causes:");
            for c in entry.common_causes {
                println!("    - {c}");
            }
        }
        if !entry.common_fixes.is_empty() {
            println!("  common fixes:");
            for f in entry.common_fixes {
                println!("    - {f}");
            }
        }
    })
}

fn normalize(code: &str) -> String {
    let trimmed: &str = code.trim();
    let upper: String = trimmed.to_ascii_uppercase();
    if upper.starts_with("DR-") && upper.matches('-').count() == 2 {
        return upper;
    }
    let bytes: &[u8] = upper.as_bytes();
    let dash: Option<usize> = bytes.iter().position(|&b| b == b'-');
    let Some(dash_pos): Option<usize> = dash else {
        return upper;
    };
    let domain: &str = &upper[..dash_pos];
    let num_part: &str = &upper[dash_pos + 1..];
    let domain_full: &str = canonicalize_domain(domain);
    if let Ok(n) = num_part.parse::<u32>() {
        return format!("DR-{domain_full}-{n:04}");
    }
    upper
}

fn canonicalize_domain(d: &str) -> &str {
    match d {
        "PYARM" | "PYARMOR" => "PYARM",
        "PYINST" | "PYINSTALLER" => "PYINST",
        "PYFRZ" | "PYFREEZE" => "PYFRZ",
        "NUITKA" => "NUITKA",
        "SDEF" | "SOURCEDEFENDER" => "SDEF",
        "PYDEOB" => "PYDEOB",
        "JSDEOB" => "JSDEOB",
        "WASMDEOB" => "WASMDEOB",
        "MARSHAL" => "MARSHAL",
        "CLI" => "CLI",
        other => other,
    }
}

fn lookup(code: &str) -> Option<&'static CodeEntry> {
    CODES.iter().find(|e| e.code == code)
}

const CODES: &[CodeEntry] = &[
    CodeEntry {
        code: "DR-CLI-0000",
        title: "subcommand not yet implemented",
        description: "the requested CLI subcommand exists in the parser but has no implementation in this build.",
        common_causes: &["running a v0.x build that still ships scaffolding stubs"],
        common_fixes: &[
            "check `disrobe --version` and `disrobe passes` to confirm which features are wired",
            "track progress at https://github.com/1-3-7/disrobe/issues",
        ],
        crate_path: "crates/disrobe-cli/src/cli/util.rs",
    },
    CodeEntry {
        code: "DR-CLI-0001",
        title: "cannot read pyarmor wrapper file",
        description: "the path given to `pyarmor unpack` could not be read as a UTF-8 text file.",
        common_causes: &[
            "file does not exist",
            "permission denied",
            "path points at a binary instead of the wrapper .py",
        ],
        common_fixes: &[
            "verify the path with `ls`/`dir`",
            "check filesystem permissions",
            "pass the wrapper .py emitted by `pyarmor obfuscate`, not the runtime DLL/SO",
        ],
        crate_path: "crates/disrobe-cli/src/cli/pyarmor.rs",
    },
    CodeEntry {
        code: "DR-CLI-0002",
        title: "cannot create pyarmor output directory",
        description: "the `--out` path could not be created on disk.",
        common_causes: &[
            "permission denied on parent dir",
            "path crosses a read-only mount",
        ],
        common_fixes: &[
            "pick a writable `--out` location",
            "create the parent directory first",
        ],
        crate_path: "crates/disrobe-cli/src/cli/pyarmor.rs",
    },
    CodeEntry {
        code: "DR-CLI-0003",
        title: "cannot write pyarmor manifest",
        description: "could not write `manifest.json` into the output dir.",
        common_causes: &["disk full", "permission revoked mid-run"],
        common_fixes: &["free disk space", "retry with a different `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/pyarmor.rs",
    },
    CodeEntry {
        code: "DR-CLI-0004",
        title: "cannot write decrypted plaintext",
        description: "post-decryption plaintext could not be written to disk.",
        common_causes: &["disk full", "permission denied"],
        common_fixes: &["check free space", "retry"],
        crate_path: "crates/disrobe-cli/src/cli/pyarmor.rs",
    },
    CodeEntry {
        code: "DR-CLI-0005",
        title: "cannot write reconstructed pyc",
        description: "the rebuilt .pyc could not be persisted.",
        common_causes: &["disk full", "permission denied"],
        common_fixes: &["check free space", "retry"],
        crate_path: "crates/disrobe-cli/src/cli/pyarmor.rs",
    },
    CodeEntry {
        code: "DR-CLI-0011",
        title: "cannot read pyinstaller input",
        description: "`pyinstaller detect|extract` could not read the binary path.",
        common_causes: &["file does not exist", "permission denied"],
        common_fixes: &["verify path", "fix permissions"],
        crate_path: "crates/disrobe-cli/src/cli/pyinstaller.rs",
    },
    CodeEntry {
        code: "DR-CLI-0012",
        title: "cannot read pyinstaller archive for extract",
        description: "`pyinstaller extract` could not load the binary into memory.",
        common_causes: &["file does not exist", "permission denied"],
        common_fixes: &["verify path", "fix permissions"],
        crate_path: "crates/disrobe-cli/src/cli/pyinstaller.rs",
    },
    CodeEntry {
        code: "DR-CLI-0013",
        title: "cannot create pyinstaller out dir",
        description: "extraction directory could not be created.",
        common_causes: &["permission denied", "parent dir missing"],
        common_fixes: &["choose a writable location"],
        crate_path: "crates/disrobe-cli/src/cli/pyinstaller.rs",
    },
    CodeEntry {
        code: "DR-CLI-0014",
        title: "cannot write pyinstaller manifest",
        description: "`manifest.json` write failed inside the pyinstaller output dir.",
        common_causes: &["disk full", "permission denied"],
        common_fixes: &["free space", "retry"],
        crate_path: "crates/disrobe-cli/src/cli/pyinstaller.rs",
    },
    CodeEntry {
        code: "DR-CLI-0015",
        title: "cannot write pyinstaller entry",
        description: "a single TOC entry from the pyinstaller archive could not be written.",
        common_causes: &[
            "disk full",
            "filename contained reserved characters on this OS",
        ],
        common_fixes: &["retry to a different `--out` on a filesystem that allows the name"],
        crate_path: "crates/disrobe-cli/src/cli/pyinstaller.rs",
    },
    CodeEntry {
        code: "DR-CLI-0016",
        title: "cannot read nuitka input",
        description: "`nuitka extract` could not read the binary path.",
        common_causes: &["file does not exist", "permission denied"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/nuitka.rs",
    },
    CodeEntry {
        code: "DR-CLI-0017",
        title: "input is not a nuitka --onefile build",
        description: "no KA[XY] onefile payload header was detected.",
        common_causes: &[
            "binary is a Nuitka --standalone build",
            "binary is not a Nuitka build at all",
        ],
        common_fixes: &[
            "use `nuitka symbols` for --standalone builds",
            "run `nuitka detect` first to confirm flavor",
        ],
        crate_path: "crates/disrobe-cli/src/cli/nuitka.rs",
    },
    CodeEntry {
        code: "DR-CLI-0018",
        title: "cannot create nuitka out dir",
        description: "`--out` directory could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["pick a writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/nuitka.rs",
    },
    CodeEntry {
        code: "DR-CLI-0019",
        title: "cannot write nuitka entry",
        description: "a payload entry write failed.",
        common_causes: &["disk full", "reserved filename characters"],
        common_fixes: &["change `--out`", "free space"],
        crate_path: "crates/disrobe-cli/src/cli/nuitka.rs",
    },
    CodeEntry {
        code: "DR-CLI-0020",
        title: "cannot read nuitka symbols input",
        description: "`nuitka symbols` could not read the binary.",
        common_causes: &["bad path", "permission denied"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/nuitka.rs",
    },
    CodeEntry {
        code: "DR-CLI-0021",
        title: "cannot create nuitka symbols dir",
        description: "parent directory for symbols.json could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["choose writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/nuitka.rs",
    },
    CodeEntry {
        code: "DR-CLI-0022",
        title: "cannot write nuitka symbols json",
        description: "symbol graph json write failed.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/nuitka.rs",
    },
    CodeEntry {
        code: "DR-CLI-0030",
        title: "cannot read py-deob input",
        description: "`py deob` could not read the source file.",
        common_causes: &["bad path", "permission denied"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0031",
        title: "cannot create py-deob out dir",
        description: "parent of `--out` could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0032",
        title: "cannot write deobfuscated python",
        description: "the rewritten source could not be written.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0033",
        title: "cannot write py-deob manifest",
        description: "the per-run manifest.json could not be written.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0034",
        title: "cannot read sourcedefender input",
        description: "`py sourcedefender` could not read the .pye file.",
        common_causes: &["bad path", "permission denied"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0035",
        title: "cannot create sourcedefender out dir",
        description: "parent of `--out` could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0036",
        title: "cannot write sourcedefender plaintext",
        description: "decrypted msgpack envelope could not be persisted.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0037",
        title: "cannot read js-deob input",
        description: "`js deob` could not read source.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/js.rs",
    },
    CodeEntry {
        code: "DR-CLI-0038",
        title: "cannot create js-deob out dir",
        description: "parent of `--out` could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/js.rs",
    },
    CodeEntry {
        code: "DR-CLI-0039",
        title: "cannot write js detection json",
        description: "the `*.detection.json` sidecar write failed.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/js.rs",
    },
    CodeEntry {
        code: "DR-CLI-0040",
        title: "cannot read wasm input",
        description: "`wasm` could not read the module.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/wasm.rs",
    },
    CodeEntry {
        code: "DR-CLI-0041",
        title: "cannot create wasm out dir",
        description: "parent of `--out` could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/wasm.rs",
    },
    CodeEntry {
        code: "DR-CLI-0042",
        title: "non utf-8 source / write failed",
        description: "either the JS source was not valid UTF-8, or the wasm summary.json write failed (two passes reuse this code).",
        common_causes: &[
            "binary file passed as JS source",
            "disk full on wasm output",
        ],
        common_fixes: &["check input charset", "free space"],
        crate_path: "crates/disrobe-cli/src/cli/{js,wasm}.rs",
    },
    CodeEntry {
        code: "DR-CLI-0043",
        title: "cannot write deobfuscated js",
        description: "the rewritten .js could not be persisted.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/js.rs",
    },
    CodeEntry {
        code: "DR-CLI-0044",
        title: "cannot write js recovery json",
        description: "the `*.recovery.json` sidecar write failed.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/js.rs",
    },
    CodeEntry {
        code: "DR-CLI-0050",
        title: "cannot read pyc input",
        description: "`py disasm` could not read the .pyc.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0051",
        title: "input is not a valid pyc",
        description: "the marshal header did not parse.",
        common_causes: &[
            "file is not a .pyc",
            "corrupt header",
            "unknown python magic",
        ],
        common_fixes: &[
            "confirm input via `file`",
            "regenerate with the matching python version",
        ],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0052",
        title: "pyc body is not a code object",
        description: "the marshalled root object was not a CodeObject.",
        common_causes: &["malformed .pyc", "wrong tool used to produce the file"],
        common_fixes: &["verify with `python -m dis` for sanity"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0053",
        title: "cannot create disasm dir",
        description: "parent of `--out` could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0054",
        title: "cannot write disasm text",
        description: "the rendered disassembly could not be written.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0055",
        title: "cannot write disasm json",
        description: "the structured disassembly json could not be written.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/py.rs",
    },
    CodeEntry {
        code: "DR-CLI-0060",
        title: "cannot create pyfreeze out dir",
        description: "extraction directory could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/pyfreeze.rs",
    },
    CodeEntry {
        code: "DR-CLI-0061",
        title: "cannot write pyfreeze manifest",
        description: "`manifest.json` write failed.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/pyfreeze.rs",
    },
    CodeEntry {
        code: "DR-CLI-0062",
        title: "pyfreeze manifest serialize failed",
        description: "the manifest could not be encoded to json.",
        common_causes: &["internal bug — please report"],
        common_fixes: &["open an issue at https://github.com/1-3-7/disrobe/issues"],
        crate_path: "crates/disrobe-cli/src/cli/pyfreeze.rs",
    },
    CodeEntry {
        code: "DR-CLI-0080",
        title: "cannot read envelope",
        description: "the .dr envelope could not be opened.",
        common_causes: &["bad path", "file is not a disrobe envelope"],
        common_fixes: &["produce one first with `envelope create`"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0081",
        title: "malformed envelope sidecar",
        description: "the postcard cold sidecar failed to decode.",
        common_causes: &[
            "envelope produced by a newer disrobe version",
            "file truncated",
        ],
        common_fixes: &["upgrade disrobe", "re-emit the envelope"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0082",
        title: "only --rung raw is implemented",
        description: "envelope create supports `--rung raw` only in v0.1.",
        common_causes: &["passed `--rung disasm` etc."],
        common_fixes: &["use `--rung raw` until other rungs land"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0083",
        title: "cannot read source for envelope create",
        description: "the input file could not be loaded.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0084",
        title: "rkyv encode failed",
        description: "encoding the raw payload to the .dr hot region failed.",
        common_causes: &["internal bug"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0085",
        title: "postcard encode failed",
        description: "encoding the cold sidecar failed.",
        common_causes: &["internal bug"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0086",
        title: "cannot write envelope",
        description: "the .dr envelope could not be written to disk.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0087",
        title: "envelope verification failed",
        description: "BLAKE3 root hash did not match the envelope payload.",
        common_causes: &["tampered envelope", "truncated file"],
        common_fixes: &["re-fetch the envelope", "regenerate"],
        crate_path: "crates/disrobe-cli/src/cli/envelope.rs",
    },
    CodeEntry {
        code: "DR-CLI-0090",
        title: "auto sniff: cannot read input",
        description: "the input file given to `disrobe auto` could not be read.",
        common_causes: &["bad path", "permission denied"],
        common_fixes: &["verify path", "fix permissions"],
        crate_path: "crates/disrobe-cli/src/cli/auto.rs",
    },
    CodeEntry {
        code: "DR-CLI-0091",
        title: "machine-format serialize failed",
        description: "could not serialize the result to json / ndjson / sarif.",
        common_causes: &["internal bug"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-cli/src/cli/output.rs",
    },
    CodeEntry {
        code: "DR-CLI-0092",
        title: "stdout write failed",
        description: "writing the machine-format result to stdout failed.",
        common_causes: &["downstream pipe closed", "redirected to read-only path"],
        common_fixes: &["redirect to a writable file"],
        crate_path: "crates/disrobe-cli/src/cli/output.rs",
    },
    CodeEntry {
        code: "DR-CLI-0093",
        title: "sarif inner serialize failed",
        description: "could not convert the inner payload to a sarif-compatible json value.",
        common_causes: &["internal bug"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-cli/src/cli/output.rs",
    },
    CodeEntry {
        code: "DR-CLI-0094",
        title: "sarif envelope serialize failed",
        description: "could not encode the final SARIF v2.1.0 envelope.",
        common_causes: &["internal bug"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-cli/src/cli/output.rs",
    },
    CodeEntry {
        code: "DR-CLI-0100",
        title: "auto: chain exceeded max depth",
        description: "the sniffer-chain hit its depth cap before reaching a terminal artifact.",
        common_causes: &["deeply nested wrappers", "cycle (same hash twice)"],
        common_fixes: &[
            "raise `--max-depth`",
            "inspect intermediate stages under out/",
        ],
        crate_path: "crates/disrobe-cli/src/cli/auto.rs",
    },
    CodeEntry {
        code: "DR-CLI-0101",
        title: "auto: cycle detected",
        description: "the sniffer-chain produced a stage whose BLAKE3 hash matched a prior stage.",
        common_causes: &[
            "pass that returns identity on its own output",
            "recursive self-wrapping",
        ],
        common_fixes: &["report the input — disrobe should grow a guard for this family"],
        crate_path: "crates/disrobe-cli/src/cli/auto.rs",
    },
    CodeEntry {
        code: "DR-CLI-0102",
        title: "explain: unknown DR code",
        description: "no documentation registered for the requested code.",
        common_causes: &["typo", "code emitted by a newer disrobe build"],
        common_fixes: &[
            "upgrade disrobe",
            "file an issue listing the code and the message you saw",
        ],
        crate_path: "crates/disrobe-cli/src/cli/explain.rs",
    },
    CodeEntry {
        code: "DR-CLI-0110",
        title: "init: target .disrobe already exists",
        description: "`disrobe init` refuses to overwrite an existing scaffold without `--force`.",
        common_causes: &["re-running init in an initialized project"],
        common_fixes: &["pass `--force` to overwrite, or remove `.disrobe/` first"],
        crate_path: "crates/disrobe-cli/src/cli/init.rs",
    },
    CodeEntry {
        code: "DR-CLI-0111",
        title: "init: cannot create .disrobe dir",
        description: "the `.disrobe/` directory could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["run with sufficient permissions"],
        crate_path: "crates/disrobe-cli/src/cli/init.rs",
    },
    CodeEntry {
        code: "DR-CLI-0112",
        title: "init: cannot write scaffold file",
        description: "writing one of the scaffold files failed mid-run.",
        common_causes: &["disk full", "permission revoked"],
        common_fixes: &["retry, then `disrobe init --force`"],
        crate_path: "crates/disrobe-cli/src/cli/init.rs",
    },
    CodeEntry {
        code: "DR-CLI-0120",
        title: "bug-report: cannot write report",
        description: "could not write the bug report to disk.",
        common_causes: &["disk full", "permission denied"],
        common_fixes: &["pick a writable `--out` or pipe to stdout via `--out -`"],
        crate_path: "crates/disrobe-cli/src/cli/bug_report.rs",
    },
    CodeEntry {
        code: "DR-CLI-0130",
        title: "man: cannot create output dir",
        description: "`disrobe man --out` directory could not be created.",
        common_causes: &["permission denied"],
        common_fixes: &["pick writable `--out`"],
        crate_path: "crates/disrobe-cli/src/cli/man.rs",
    },
    CodeEntry {
        code: "DR-CLI-0131",
        title: "man: render failed",
        description: "`clap_mangen` failed to render a subcommand page.",
        common_causes: &["internal bug — clap signature change"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-cli/src/cli/man.rs",
    },
    CodeEntry {
        code: "DR-CLI-0132",
        title: "man: cannot write page",
        description: "writing the .1 page failed.",
        common_causes: &["disk full"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-cli/src/cli/man.rs",
    },
    CodeEntry {
        code: "DR-CLI-0140",
        title: "completions install: cannot locate shell config",
        description: "could not figure out which rc file to update for the requested shell.",
        common_causes: &["uncommon shell layout", "missing HOME / PROFILE env"],
        common_fixes: &["pass `--rc-file` to point at your rc explicitly"],
        crate_path: "crates/disrobe-cli/src/cli/completions.rs",
    },
    CodeEntry {
        code: "DR-CLI-0141",
        title: "completions install: cannot write rc file",
        description: "appending the source line to the rc file failed.",
        common_causes: &["permission denied"],
        common_fixes: &["chown/chmod the rc file"],
        crate_path: "crates/disrobe-cli/src/cli/completions.rs",
    },
    CodeEntry {
        code: "DR-CLI-0150",
        title: "status: cannot read out/ tree",
        description: "could not walk the working directory's `out/` tree.",
        common_causes: &["permission denied"],
        common_fixes: &["fix permissions"],
        crate_path: "crates/disrobe-cli/src/cli/status.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0001",
        title: "input does not appear to be a PyArmor wrapper",
        description: "the file did not match any known PyArmor wrapper layout.",
        common_causes: &[
            "plain python source",
            "wrapper from an unknown PyArmor version",
        ],
        common_fixes: &[
            "confirm via `pyarmor inspect` upstream",
            "open an issue with a redacted sample",
        ],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0002",
        title: "unknown PyArmor wrapper format",
        description: "the wrapper shape did not match v6/v7/v8/v9 grammar.",
        common_causes: &["new PyArmor release", "custom build"],
        common_fixes: &["file an issue with the wrapper's first 200 lines"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0003",
        title: "payload bytes literal missing",
        description: "the embedded `b'...'` payload could not be located in the wrapper.",
        common_causes: &[
            "custom wrapper layout",
            "wrapper has been further obfuscated",
        ],
        common_fixes: &["run `py deob` first to peel the outer encoder"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0004",
        title: "PyArmor runtime extension not found",
        description: "no pyarmor runtime DLL/SO was located next to the wrapper.",
        common_causes: &[
            "sample shipped without runtime",
            "runtime is at a custom path",
        ],
        common_fixes: &["place the runtime DLL/SO in the same dir as the wrapper"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0005",
        title: "PyArmor v8/v9 header truncated",
        description: "the v8/v9 header was shorter than the expected fixed length.",
        common_causes: &["truncated download", "wrong file"],
        common_fixes: &["re-fetch the sample"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0006",
        title: "PyArmor v8/v9 magic mismatch",
        description: "expected `PY` + 6 digits magic was not present.",
        common_causes: &["sample is not v8/v9"],
        common_fixes: &["try the v6/v7 path"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0007",
        title: "PyArmor v6/v7 magic mismatch",
        description: "expected `PYARMOR\\0` magic was not present.",
        common_causes: &["sample is not v6/v7"],
        common_fixes: &["try the v8/v9 path", "verify with `pyarmor inspect`"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0008",
        title: "runtime DLL parse failed",
        description: "could not parse the PyArmor runtime extension.",
        common_causes: &["corrupt runtime", "unsupported runtime version"],
        common_fixes: &["ensure the runtime matches the wrapper version"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0009",
        title: "AES key extraction failed",
        description: "could not recover the AES key from the runtime.",
        common_causes: &[
            "runtime patched with non-default key derivation",
            "BCC mode in use",
        ],
        common_fixes: &["try `--allow-dynamic` to capture the runtime in a sandbox"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0010",
        title: "AES decryption failed",
        description: "the recovered key did not yield valid marshal output.",
        common_causes: &["wrong key extracted", "wrong IV"],
        common_fixes: &["try the dynamic hook fallback"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0011",
        title: "marshal decode error after decrypt",
        description: "the decrypted bytes did not parse as Python marshal.",
        common_causes: &["wrong decrypted payload", "outer layer not stripped"],
        common_fixes: &["re-run with `RUST_LOG=debug` and report the marshal offset"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0012",
        title: "pyarmor I/O error",
        description: "underlying I/O error reading input or runtime.",
        common_causes: &["bad paths", "permission denied"],
        common_fixes: &["fix paths/permissions"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0013",
        title: "PyArmor v3/v4/v5 not yet implemented",
        description: "legacy PyArmor versions are not yet supported (samples scarce).",
        common_causes: &["very old protected artifact"],
        common_fixes: &["file an issue with a sample if you can share one"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0014",
        title: "BCC mode is partial-only",
        description: "BCC payloads require a native lifter; only the Python half is recoverable today.",
        common_causes: &["sample built with PyArmor BCC mode"],
        common_fixes: &[
            "accept partial recovery",
            "use `nuitka symbols`-style approach for the native side",
        ],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0015",
        title: "hex/escape decoding of wrapper bytes failed",
        description: "the Python bytes literal contained an escape sequence we cannot decode.",
        common_causes: &["wrapper post-processed by another obfuscator"],
        common_fixes: &["peel the outer obfuscator with `py deob` first"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0016",
        title: "dynamic hook required but not allowed",
        description: "static unpack failed and the dynamic-hook fallback was not enabled.",
        common_causes: &["v6/v7 sample with non-default key derivation"],
        common_fixes: &["re-run with `--allow-dynamic` inside a sandbox"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0017",
        title: "no usable Python found for dynamic hook",
        description: "no Python >= 3.9.7 was located on PATH.",
        common_causes: &["python not installed", "pyenv shim points elsewhere"],
        common_fixes: &[
            "install Python 3.9.7+",
            "set DISROBE_PYTHON to a usable interpreter",
        ],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0018",
        title: "dynamic hook timed out",
        description: "the watchdog killed the subprocess.",
        common_causes: &["sample exits slowly", "sample is interactive"],
        common_fixes: &["raise `--dynamic-timeout`"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0019",
        title: "dynamic hook subprocess error",
        description: "the dynamic-hook subprocess exited with a non-zero status.",
        common_causes: &["sample raised during import", "missing Python deps"],
        common_fixes: &["check the captured stderr in the output dir"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0020",
        title: "dynamic hook produced zero captures",
        description: "the subprocess ran but no marshal streams were captured.",
        common_causes: &[
            "sample exited before reaching protected code",
            "anti-debug check tripped",
        ],
        common_fixes: &["increase timeout, retry on a different host"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYARM-0021",
        title: "dynamic hook found python too old",
        description: "the located Python interpreter is older than the required 3.9.7.",
        common_causes: &["system python is 3.8 or older"],
        common_fixes: &["install a newer Python and set DISROBE_PYTHON"],
        crate_path: "crates/disrobe-pass-pyarmor/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0001",
        title: "PyInstaller MEI cookie not found",
        description: "the MEI cookie magic was not located in the binary.",
        common_causes: &[
            "binary is not a PyInstaller build",
            "binary was repacked / stripped",
        ],
        common_fixes: &[
            "confirm with strings | grep MEI",
            "try `nuitka detect` / `pyfreeze detect` instead",
        ],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0002",
        title: "PyInstaller cookie truncated",
        description: "the cookie header ran off the end of the file.",
        common_causes: &["truncated download"],
        common_fixes: &["re-fetch the sample"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0003",
        title: "PyInstaller I/O error",
        description: "underlying I/O error reading the binary.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0004",
        title: "PyInstaller TOC walk failed",
        description: "the table-of-contents walk produced an inconsistent entry.",
        common_causes: &["repacked archive", "custom packer"],
        common_fixes: &["re-fetch sample", "open an issue with the cookie offsets"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0005",
        title: "zlib inflate failed for entry",
        description: "a compressed TOC entry could not be decompressed.",
        common_causes: &["entry was AES-encrypted with no key provided"],
        common_fixes: &["if PyInstaller >= 6.0, decrypt with the bundled key first"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0006",
        title: "PyInstaller AES decrypt failed",
        description: "AES decryption produced invalid plaintext.",
        common_causes: &["wrong key", "PyInstaller >= 6.0 with custom key derivation"],
        common_fixes: &["supply key via PyInstaller hooks fork", "file an issue"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0007",
        title: "PyInstaller bad PYZ magic",
        description: "the inner PYZ archive did not start with `PYZ\\0`.",
        common_causes: &["corrupted archive"],
        common_fixes: &["re-fetch sample"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0008",
        title: "PyInstaller PYZ TOC marshal decode",
        description: "the PYZ table-of-contents marshal payload did not parse.",
        common_causes: &["wrong python version assumed", "corrupted PYZ"],
        common_fixes: &["use `pyinstaller detect` to confirm pyver"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0009",
        title: "PyInstaller path traversal",
        description: "a TOC entry name attempted to escape the output dir.",
        common_causes: &["malicious archive"],
        common_fixes: &["sample blocked; do not bypass"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYINST-0010",
        title: "PyInstaller bad pyver",
        description: "the pyver field did not decode to (major, minor).",
        common_causes: &["unknown PyInstaller bootloader fork"],
        common_fixes: &["open an issue with the cookie hex dump"],
        crate_path: "crates/disrobe-pass-pyinstaller/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0001",
        title: "not a Nuitka build",
        description: "no Nuitka signatures detected.",
        common_causes: &["binary is from a different packer"],
        common_fixes: &["try `pyinstaller detect` / `pyfreeze detect`"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0002",
        title: "nuitka I/O error",
        description: "I/O failed while reading the binary.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0003",
        title: "PE/ELF/Mach-O parse error",
        description: "the executable header did not parse.",
        common_causes: &["truncated binary"],
        common_fixes: &["re-fetch"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0004",
        title: "nuitka onefile magic mismatch",
        description: "expected KA[XY] magic was not present.",
        common_causes: &["not a --onefile build"],
        common_fixes: &["use `nuitka symbols` instead"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0005",
        title: "nuitka zstd decompression failed",
        description: "the onefile payload could not be decompressed.",
        common_causes: &["corrupt sample"],
        common_fixes: &["re-fetch"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0006",
        title: "nuitka entry record truncated",
        description: "a per-entry record ran off the end of the payload.",
        common_causes: &["corrupt or truncated payload"],
        common_fixes: &["re-fetch sample"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0007",
        title: "nuitka source recovery impossible",
        description: "Nuitka emits native machine code; source-level recovery is mathematically impossible.",
        common_causes: &["asking the wrong tool"],
        common_fixes: &[
            "use `nuitka symbols` for constants/symbols, then a native decompiler for the C++ side",
        ],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0008",
        title: "nuitka build-info missing",
        description: "the build-info section was not located in the image.",
        common_causes: &["stripped binary"],
        common_fixes: &["pass `-v` to expose more diagnostics"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0009",
        title: "nuitka build-info malformed",
        description: "the build-info record did not parse.",
        common_causes: &["unsupported Nuitka version"],
        common_fixes: &["open an issue with version + first 64 bytes"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-NUITKA-0010",
        title: "nuitka reassembly needs >=1 entry",
        description: "the payload was empty.",
        common_causes: &["corrupted onefile"],
        common_fixes: &["re-fetch sample"],
        crate_path: "crates/disrobe-pass-nuitka/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0001",
        title: "not a sourcedefender .pye",
        description: "BEGIN/END markers were not found.",
        common_causes: &["wrong file"],
        common_fixes: &["confirm extension; pass the original .pye"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0002",
        title: "sourcedefender I/O error",
        description: "I/O failure reading the .pye.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0003",
        title: "sourcedefender empty filename",
        description: "the filename is empty, so the filename-derived password cannot be computed.",
        common_causes: &["empty path"],
        common_fixes: &["pass a non-empty filename"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0004",
        title: "sourcedefender base85 decode failed",
        description: "the IV or ciphertext base85 block did not decode.",
        common_causes: &["wrong file", "tampered envelope"],
        common_fixes: &["regenerate sourcedefender output"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0005",
        title: "sourcedefender bad IV length",
        description: "IV was not 16 bytes.",
        common_causes: &["wrong file"],
        common_fixes: &["regenerate"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0006",
        title: "sourcedefender blake2 error",
        description: "internal blake2b error.",
        common_causes: &["internal bug"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0007",
        title: "sourcedefender not UTF-8",
        description: "the .pye envelope must be UTF-8.",
        common_causes: &["binary garbage"],
        common_fixes: &["verify input"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0008",
        title: "sourcedefender msgpack decode failed",
        description: "the inner msgpack envelope did not parse.",
        common_causes: &["corrupt payload"],
        common_fixes: &["regenerate"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0009",
        title: "sourcedefender inlined filename missing",
        description: "the inlined envelope did not carry a filename hint.",
        common_causes: &["non-standard inlined layout"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-SDEF-0010",
        title: "sourcedefender inlined no decrypt",
        description: "found blocks but none decrypted successfully.",
        common_causes: &["wrong filename hint", "tampered envelope"],
        common_fixes: &["pass the correct filename"],
        crate_path: "crates/disrobe-pass-sourcedefender/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0001",
        title: "no obfuscation family matched",
        description: "the source did not match any known python obfuscator pattern.",
        common_causes: &["plain code", "very rare obfuscator"],
        common_fixes: &["file an issue with a sample"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0002",
        title: "py-deob I/O error",
        description: "I/O failed.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0003",
        title: "py-deob depth limit reached",
        description: "encoder peel hit the depth cap without converging.",
        common_causes: &["very deeply nested encoder", "non-terminating obfuscator"],
        common_fixes: &["report sample for investigation"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0004",
        title: "py-deob base64 decode failed",
        description: "an intermediate base64 layer did not decode.",
        common_causes: &["custom alphabet", "corrupted source"],
        common_fixes: &["re-fetch the sample"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0005",
        title: "py-deob zlib decompression failed",
        description: "an intermediate zlib layer did not decompress.",
        common_causes: &["wrong layer detected"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0006",
        title: "py-deob lzma decompression failed",
        description: "an intermediate lzma layer did not decompress.",
        common_causes: &["wrong layer detected"],
        common_fixes: &["open an issue"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0007",
        title: "py-deob bytes literal not found",
        description: "the obfuscator's bytes literal was not located.",
        common_causes: &["unusual wrapper layout"],
        common_fixes: &["report sample"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0008",
        title: "py-deob invalid utf-8 in output",
        description: "the deobfuscated bytes were not valid UTF-8 python source.",
        common_causes: &["wrong layer detected"],
        common_fixes: &["report sample"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYDEOB-0009",
        title: "py-deob AST cleanup failed",
        description: "ruff-AST cleanup pass errored out.",
        common_causes: &["invalid python in intermediate stage"],
        common_fixes: &["disable `--cleanup` and inspect"],
        crate_path: "crates/disrobe-pass-py-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-JSDEOB-0001",
        title: "no JS obfuscator family matched",
        description: "the source did not match any known JS obfuscator pattern.",
        common_causes: &["plain JS"],
        common_fixes: &["nothing to deobfuscate"],
        crate_path: "crates/disrobe-pass-js-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-JSDEOB-0002",
        title: "js-deob I/O error",
        description: "I/O failed.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-pass-js-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-JSDEOB-0003",
        title: "js-deob oxc parse error",
        description: "the oxc parser rejected the source.",
        common_causes: &["malformed JS", "unsupported syntax"],
        common_fixes: &["check input with a JS validator"],
        crate_path: "crates/disrobe-pass-js-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-JSDEOB-0004",
        title: "js-deob invalid utf-8",
        description: "the JS source was not UTF-8.",
        common_causes: &["binary input"],
        common_fixes: &["pass valid UTF-8"],
        crate_path: "crates/disrobe-pass-js-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-WASMDEOB-0001",
        title: "not a valid WebAssembly module",
        description: "wasmparser rejected the binary.",
        common_causes: &["wrong file", "truncated module"],
        common_fixes: &["validate with `wasm-validate`"],
        crate_path: "crates/disrobe-pass-wasm-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-WASMDEOB-0002",
        title: "wasm-deob I/O error",
        description: "I/O failed.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-pass-wasm-deob/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0001",
        title: "not a recognized python freezer container",
        description: "input did not look like cx_Freeze / py2exe / shiv / pex / PyOxidizer / Briefcase.",
        common_causes: &["wrong tool", "unknown freezer"],
        common_fixes: &["try other passes"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0002",
        title: "pyfreeze I/O error",
        description: "I/O failed.",
        common_causes: &["bad path"],
        common_fixes: &["verify path"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0003",
        title: "cx_Freeze missing sibling layout",
        description: "required sibling files were missing next to the binary.",
        common_causes: &["partial install"],
        common_fixes: &["copy the full bundle (lib/, python*.dll, etc.)"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0004",
        title: "py2exe PYTHONSCRIPT resource missing",
        description: "the PE resource was not present.",
        common_causes: &["repacked py2exe"],
        common_fixes: &["confirm with a resource viewer"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0005",
        title: "py2exe scriptinfo tag mismatch",
        description: "expected 0x78563412 tag absent.",
        common_causes: &["corrupted resource"],
        common_fixes: &["re-fetch sample"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0006",
        title: "py2exe scriptinfo truncated",
        description: "scriptinfo body shorter than required.",
        common_causes: &["truncated PE"],
        common_fixes: &["re-fetch"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0007",
        title: "shiv missing _bootstrap/",
        description: "shiv archive missing required bootstrap dir.",
        common_causes: &["repacked shiv"],
        common_fixes: &["use original shiv output"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0008",
        title: "shiv missing environment.json",
        description: "shiv manifest missing.",
        common_causes: &["repacked"],
        common_fixes: &["use original"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0009",
        title: "pex missing PEX-INFO",
        description: "pex manifest missing.",
        common_causes: &["repacked"],
        common_fixes: &["use original"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0010",
        title: "trailing zip EOCD missing",
        description: "end-of-central-directory record was not found in the trailing zip.",
        common_causes: &["truncated archive"],
        common_fixes: &["re-fetch"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0011",
        title: "zip parse failed",
        description: "the embedded zip did not parse.",
        common_causes: &["custom compression"],
        common_fixes: &["report sample"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0012",
        title: "zip entry extraction failed",
        description: "a single zip entry could not be decompressed/written.",
        common_causes: &["disk full", "filename collision"],
        common_fixes: &["free space"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0013",
        title: "pyfreeze PE parse failed",
        description: "the PE header did not parse.",
        common_causes: &["truncated"],
        common_fixes: &["re-fetch"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0014",
        title: "shebang invalid",
        description: "shebang manifest line did not match shiv/pex grammar.",
        common_causes: &["modified bootstrap"],
        common_fixes: &["use original output"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0015",
        title: "unsafe archive entry path",
        description: "entry name attempted to escape the container root.",
        common_causes: &["malicious archive"],
        common_fixes: &["blocked; do not bypass"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0016",
        title: "payload decompression failed",
        description: "the inner payload could not be decompressed.",
        common_causes: &["custom compression"],
        common_fixes: &["report sample"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0017",
        title: "json manifest parse failed",
        description: "the freezer's JSON manifest did not parse.",
        common_causes: &["custom freezer version"],
        common_fixes: &["report sample"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0018",
        title: "pyfreeze quota exceeded",
        description: "extraction quota guard tripped on an entry.",
        common_causes: &["zip-bomb-style archive"],
        common_fixes: &["raise quota via env or refuse the sample"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0019",
        title: "PyOxidizer config block missing",
        description: "no embedded Python configuration was located in the PyOxidizer build.",
        common_causes: &["older PyOxidizer build"],
        common_fixes: &["report sample"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-PYFRZ-0020",
        title: "Briefcase missing sibling layout",
        description: "Briefcase support requires sibling files we could not find.",
        common_causes: &["partial bundle"],
        common_fixes: &["copy the full Briefcase output"],
        crate_path: "crates/disrobe-pass-pyfreeze/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0001",
        title: "marshal EOF",
        description: "input ran out before parsing completed.",
        common_causes: &["truncated marshal payload"],
        common_fixes: &["re-fetch source bytes"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0002",
        title: "marshal unknown tag",
        description: "an unrecognized marshal type byte was seen.",
        common_causes: &["wrong python version assumed"],
        common_fixes: &["pass correct pyver"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0003",
        title: "marshal invalid utf-8",
        description: "a marshal string was not valid UTF-8.",
        common_causes: &["wrong python version"],
        common_fixes: &["pass correct pyver"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0004",
        title: "marshal ref-table OOB",
        description: "back-reference index exceeded ref table size.",
        common_causes: &["corrupted marshal stream"],
        common_fixes: &["re-fetch source"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0005",
        title: "code object shape mismatch",
        description: "code object field count did not match the python era.",
        common_causes: &["wrong python version assumed"],
        common_fixes: &["pass correct pyver"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0006",
        title: "unsupported python version",
        description: "the python version reported by the header is not yet supported.",
        common_causes: &["very new or very old python"],
        common_fixes: &["file an issue listing the magic / pyver"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0007",
        title: "pyc header too short",
        description: "the pyc header was truncated.",
        common_causes: &["wrong file passed as pyc"],
        common_fixes: &["confirm with `file`"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0008",
        title: "unknown pyc magic",
        description: "the pyc magic number does not map to any known python version.",
        common_causes: &["very new / custom build"],
        common_fixes: &["file an issue"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0009",
        title: "marshal depth limit exceeded",
        description: "the marshal nesting depth exceeded the safety limit.",
        common_causes: &["pathological input"],
        common_fixes: &["refuse the sample"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0010",
        title: "long-int digit count too large",
        description: "long-int field would allocate beyond the sanity cap.",
        common_causes: &["pathological input"],
        common_fixes: &["refuse the sample"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0011",
        title: "container length too large",
        description: "tuple/list/dict length exceeded the sanity cap.",
        common_causes: &["pathological input"],
        common_fixes: &["refuse the sample"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
    CodeEntry {
        code: "DR-MARSHAL-0012",
        title: "marshal writer length overflow",
        description: "payload exceeded the marshal u32 size field max.",
        common_causes: &["asked to encode oversize payload"],
        common_fixes: &["split into smaller chunks"],
        crate_path: "crates/disrobe-py-marshal/src/error.rs",
    },
];

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn normalize_long_form_passes_through() {
        assert_eq!(normalize("DR-PYARM-0007"), "DR-PYARM-0007");
        assert_eq!(normalize("dr-pyarm-0007"), "DR-PYARM-0007");
    }

    #[test]
    fn normalize_short_form_expands_with_padding() {
        assert_eq!(normalize("pyarm-7"), "DR-PYARM-0007");
        assert_eq!(normalize("nuitka-3"), "DR-NUITKA-0003");
        assert_eq!(normalize("pyarmor-7"), "DR-PYARM-0007");
        assert_eq!(normalize("pyinstaller-1"), "DR-PYINST-0001");
        assert_eq!(normalize("pyfreeze-20"), "DR-PYFRZ-0020");
        assert_eq!(normalize("sourcedefender-5"), "DR-SDEF-0005");
    }

    #[test]
    fn every_registered_code_is_well_formed() {
        for entry in CODES {
            assert!(entry.code.starts_with("DR-"), "{}", entry.code);
            assert_eq!(entry.code.matches('-').count(), 2, "{}", entry.code);
            let num_part: &str = entry.code.rsplit('-').next().unwrap_or("");
            assert_eq!(num_part.len(), 4, "{}", entry.code);
            assert!(
                num_part.parse::<u32>().is_ok(),
                "non-numeric tail in {}",
                entry.code
            );
            assert!(!entry.title.is_empty());
            assert!(!entry.description.is_empty());
            assert!(!entry.crate_path.is_empty());
        }
    }

    #[test]
    fn lookup_finds_pyarm_seven() {
        let e: &CodeEntry = lookup("DR-PYARM-0007").expect("present");
        assert!(e.title.contains("v6/v7"));
    }

    #[test]
    fn lookup_misses_made_up_code() {
        assert!(lookup("DR-MADEUP-9999").is_none());
    }
}
