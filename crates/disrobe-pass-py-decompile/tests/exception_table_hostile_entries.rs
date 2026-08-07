#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::find_interpreter;
use disrobe_pass_py_decompile::bytecode::flow::{
    ExceptionTableEntry, followable_exception_entries, parse_exception_table,
};
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const TABLE_ERA: &[&str] = &["3.11", "3.12", "3.13", "3.14", "3.15"];

const SOURCE: &str = "def f(mgr, nxt, sink):\n    try:\n        sink(nxt())\n    except \
                      LookupError:\n        sink(None)\n    with mgr() as handle:\n        \
                      sink(handle)\n    return handle\n";

#[derive(Debug, Clone, Copy)]
enum Hostile {
    ZeroLength,
    TargetPastEnd,
    TargetMidInstruction,
    PartialOverlap,
}

impl Hostile {
    const fn label(self) -> &'static str {
        match self {
            Self::ZeroLength => "zero-length protected range",
            Self::TargetPastEnd => "handler target past the end of the code",
            Self::TargetMidInstruction => "handler target inside an instruction",
            Self::PartialOverlap => "range that straddles the edge of a real range",
        }
    }
}

const HOSTILE: [Hostile; 4] = [
    Hostile::ZeroLength,
    Hostile::TargetPastEnd,
    Hostile::TargetMidInstruction,
    Hostile::PartialOverlap,
];

fn encode_varint(value: u32, first_of_entry: bool, out: &mut Vec<u8>) {
    let mut chunks: Vec<u8> = Vec::with_capacity(6);
    let mut remaining: u32 = value;
    loop {
        chunks.push(u8::try_from(remaining & 0x3F).unwrap_or(0));
        remaining >>= 6;
        if remaining == 0 {
            break;
        }
    }
    let last: usize = chunks.len() - 1;
    for (position, chunk) in chunks.iter().rev().enumerate() {
        let continues: u8 = if position == last { 0 } else { 0x40 };
        let marker: u8 = if position == 0 && first_of_entry {
            0x80
        } else {
            0
        };
        out.push(chunk | continues | marker);
    }
}

fn encode_table(entries: &[ExceptionTableEntry]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(entries.len() * 8);
    for entry in entries {
        encode_varint(entry.start / 2, true, &mut out);
        encode_varint(entry.length / 2, false, &mut out);
        encode_varint(entry.target / 2, false, &mut out);
        encode_varint(
            (u32::from(entry.depth) << 1) | u32::from(entry.lasti),
            false,
            &mut out,
        );
    }
    out
}

fn compile_source(interpreter: &Path, source_path: &Path, pyc_path: &Path) -> Result<(), String> {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "exit={:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile = read_pyc(&bytes).map_err(|e| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn nested_function(module: &CodeObject) -> Option<CodeObject> {
    module.consts.iter().find_map(|value: &Object| match value {
        Object::Code(boxed) => Some((**boxed).clone()),
        _ => None,
    })
}

fn instruction_offsets(code: &CodeObject, version: &PyVersion) -> Vec<u32> {
    let opmap: Box<dyn disrobe_pass_py_decompile::bytecode::opcode::OpcodeMap> =
        disrobe_pass_py_decompile::bytecode::opcode::map_for(version.clone());
    let mut offsets: Vec<u32> = Vec::new();
    let mut cursor: usize = 0;
    while cursor + 1 < code.code.len() {
        let raw: u8 = code.code[cursor];
        offsets.push(u32::try_from(cursor).unwrap_or(u32::MAX));
        cursor += 2 + usize::from(opmap.cache_size(raw)) * 2;
    }
    offsets
}

fn hostile_entry(
    kind: Hostile,
    real: &[ExceptionTableEntry],
    offsets: &[u32],
    code_len: u32,
) -> Option<ExceptionTableEntry> {
    let anchor: ExceptionTableEntry = *real.first()?;
    match kind {
        Hostile::ZeroLength => Some(ExceptionTableEntry {
            length: 0,
            ..anchor
        }),
        Hostile::TargetPastEnd => Some(ExceptionTableEntry {
            length: 2,
            target: code_len.saturating_add(64),
            ..anchor
        }),
        Hostile::TargetMidInstruction => {
            let cache_slot: u32 = (0..code_len)
                .step_by(2)
                .find(|slot: &u32| offsets.binary_search(slot).is_err())?;
            Some(ExceptionTableEntry {
                length: 2,
                target: cache_slot,
                ..anchor
            })
        }
        Hostile::PartialOverlap => {
            let wide: ExceptionTableEntry = *real
                .iter()
                .find(|entry: &&ExceptionTableEntry| entry.length > 4)?;
            let inside: u32 = *offsets
                .iter()
                .find(|&&offset: &&u32| offset > wide.start && offset < wide.end())?;
            let end: u32 = wide.end().checked_add(2).filter(|e: &u32| *e <= code_len)?;
            Some(ExceptionTableEntry {
                start: inside,
                length: end - inside,
                ..wide
            })
        }
    }
}

#[test]
fn a_hostile_exception_table_entry_is_rejected_rather_than_followed() {
    let scratch: PathBuf = PathBuf::from("../../target/py-hostile-exception-table");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut graded: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut skipped: Vec<&str> = Vec::new();

    for &alias in TABLE_ERA {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            skipped.push(alias);
            continue;
        };
        let source_path: PathBuf = scratch.join(format!("region.{alias}.py"));
        fs::write(&source_path, SOURCE).expect("write fixture");
        let pyc_path: PathBuf = scratch.join(format!("region.{alias}.pyc"));
        compile_source(&interpreter, &source_path, &pyc_path)
            .unwrap_or_else(|e| panic!("py{alias} compile: {e}"));
        let (module, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&pyc_path).unwrap_or_else(|e| panic!("py{alias} read: {e}"));
        let version: PyVersion = marshal_to_decompile(marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} version map: {e:?}"));
        let original: CodeObject =
            nested_function(&module).unwrap_or_else(|| panic!("py{alias}: no nested function"));

        let real: Vec<ExceptionTableEntry> = parse_exception_table(&original.exceptiontable)
            .unwrap_or_else(|e| panic!("py{alias} parse: {e}"));
        assert!(
            !real.is_empty(),
            "py{alias}: the fixture must carry a real exception table or this case grades nothing"
        );
        let code_len: u32 = u32::try_from(original.code.len()).unwrap_or(u32::MAX);
        let offsets: Vec<u32> = instruction_offsets(&original, &version);
        assert_eq!(
            followable_exception_entries(&real, &offsets, code_len),
            real,
            "py{alias}: the table CPython emitted must survive the check unchanged"
        );

        let clean_module: String = build_real_source(&module, &version, marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} decompile: {e}"));
        let clean_path: PathBuf = scratch.join(format!("region.clean.{alias}.py"));
        fs::write(&clean_path, &clean_module).expect("write clean");
        let clean_pyc: PathBuf = scratch.join(format!("region.clean.{alias}.pyc"));
        compile_source(&interpreter, &clean_path, &clean_pyc)
            .unwrap_or_else(|e| panic!("py{alias} recompile clean: {e}"));
        let (recompiled, _): (CodeObject, MarshalVersion) =
            read_code(&clean_pyc).unwrap_or_else(|e| panic!("py{alias} read clean: {e}"));
        assert!(
            matches!(
                semantic_equiv(&module, &recompiled, marshal_version),
                Verdict::Perfect | Verdict::Semantic
            ),
            "py{alias}: the clean fixture must recover to equivalent bytecode, otherwise every \
             comparison below grades one wrong answer against another\n{clean_module}"
        );

        for kind in HOSTILE {
            let Some(injected): Option<ExceptionTableEntry> =
                hostile_entry(kind, &real, &offsets, code_len)
            else {
                failures.push(format!(
                    "py{alias}/{}: the fixture cannot express this shape, so the case grades \
                     nothing",
                    kind.label()
                ));
                continue;
            };
            let mut mutated: Vec<ExceptionTableEntry> = real.clone();
            mutated.push(injected);
            let kept: Vec<ExceptionTableEntry> =
                followable_exception_entries(&mutated, &offsets, code_len);
            graded += 1;
            if kept != real {
                failures.push(format!(
                    "py{alias}/{}: the check kept {} entries instead of the {} CPython emitted",
                    kind.label(),
                    kept.len(),
                    real.len()
                ));
                continue;
            }

            let mut hostile_module: CodeObject = module.clone();
            let mut hostile_function: CodeObject = original.clone();
            hostile_function.exceptiontable = encode_table(&mutated);
            for value in &mut hostile_module.consts {
                if matches!(value, Object::Code(_)) {
                    *value = Object::Code(Box::new(hostile_function.clone()));
                    break;
                }
            }
            let round_trip: Vec<ExceptionTableEntry> =
                parse_exception_table(&hostile_function.exceptiontable)
                    .unwrap_or_else(|e| panic!("py{alias} reparse: {e}"));
            assert_eq!(
                round_trip,
                mutated,
                "py{alias}/{}: the injected table must survive encoding, or the decompiler never \
                 sees the entry this case is about",
                kind.label()
            );

            match build_real_source(&hostile_module, &version, marshal_version) {
                Ok(recovered) if recovered == clean_module => {}
                Ok(recovered) => failures.push(format!(
                    "py{alias}/{}: the decompiler followed the injected entry and recovered \
                     different source\n{recovered}",
                    kind.label()
                )),
                Err(e) => failures.push(format!(
                    "py{alias}/{}: the decompiler failed on the injected entry: {e}",
                    kind.label()
                )),
            }
        }
    }

    if !skipped.is_empty() {
        println!("NOT MEASURED on {skipped:?}: `uv python install <version>` resolves them");
    }
    assert!(
        graded > 0,
        "no CPython 3.11 through 3.15 interpreter resolved, so this case graded nothing"
    );
    assert!(
        failures.is_empty(),
        "{} hostile exception table failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
