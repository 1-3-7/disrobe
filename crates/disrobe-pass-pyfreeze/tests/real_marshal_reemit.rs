#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_pyfreeze::recover::synthesize_pyc;
use disrobe_py_marshal::{Object, PyVersion, PycFile, magic_for, read_pyc};

const MARKER: &str = "caf\u{e9}-\u{65e5}\u{672c}\u{8a9e}-\u{2603}";

const GEN_SCRIPT: &str = "\
import sys, marshal
marker = \"caf\\u00e9-\\u65e5\\u672c\\u8a9e-\\u2603\"
mod_src = \"GREETING = %r\\nNEG_ZERO = -0.0\\nBIG = 1e400\\nNBIG = -1e400\\ndef f():\\n    return GREETING\\n\" % (marker,)
code = compile(mod_src, \"<reemit>\", \"exec\")
with open(sys.argv[1], \"wb\") as fh:
    fh.write(marshal.dumps(code))
tup = (-0.0, float(\"nan\"), float(\"inf\"), float(\"-inf\"), marker)
with open(sys.argv[2], \"wb\") as fh:
    fh.write(marshal.dumps(tup))
sys.stdout.write(\"%d.%d\" % (sys.version_info[0], sys.version_info[1]))
";

const INSPECT_SCRIPT: &str = "\
import sys, marshal, struct
def walk(o, fs, ss):
    if isinstance(o, bool):
        return
    if isinstance(o, str):
        ss.append(o)
    elif isinstance(o, float):
        fs.append(struct.pack(\"<d\", o).hex())
    elif isinstance(o, complex):
        fs.append(struct.pack(\"<d\", o.real).hex())
        fs.append(struct.pack(\"<d\", o.imag).hex())
    elif isinstance(o, (tuple, list, set, frozenset)):
        for x in o:
            walk(x, fs, ss)
    elif hasattr(o, \"co_consts\"):
        for x in o.co_consts:
            walk(x, fs, ss)
with open(sys.argv[1], \"rb\") as fh:
    data = fh.read()
fs = []
ss = []
walk(marshal.loads(data), fs, ss)
marker = \"caf\\u00e9-\\u65e5\\u672c\\u8a9e-\\u2603\"
lines = [\"F \" + h for h in fs]
lines.append(\"MARKER \" + (\"1\" if any(marker in s for s in ss) else \"0\"))
sys.stdout.write(\"\\n\".join(lines))
";

type GeneratedMarshal = ((u8, u8), Vec<u8>, Vec<u8>);

const fn python_cmd() -> &'static str {
    if cfg!(windows) { "py" } else { "python3" }
}

fn workdir(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq: u64 = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-reemit-{tag}-{}-{}",
        std::process::id(),
        seq
    ));
    std::fs::create_dir_all(&dir).expect("mk workdir");
    dir
}

fn run_generator(dir: &Path) -> Option<GeneratedMarshal> {
    let script: PathBuf = dir.join("gen.py");
    std::fs::write(&script, GEN_SCRIPT).expect("write gen script");
    let mod_out: PathBuf = dir.join("module.marshal");
    let tup_out: PathBuf = dir.join("tuple.marshal");
    let output: std::process::Output = Command::new(python_cmd())
        .arg(&script)
        .arg(&mod_out)
        .arg(&tup_out)
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!(
            "[real_marshal_reemit] generator exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    let ver_text: String = String::from_utf8(output.stdout).ok()?;
    let (maj_s, min_s): (&str, &str) = ver_text.trim().split_once('.')?;
    let major: u8 = maj_s.parse().ok()?;
    let minor: u8 = min_s.parse().ok()?;
    let module: Vec<u8> = std::fs::read(&mod_out).ok()?;
    let tuple: Vec<u8> = std::fs::read(&tup_out).ok()?;
    Some(((major, minor), module, tuple))
}

fn cpython_inspect(dir: &Path, marshal_path: &Path) -> Option<(Vec<u64>, bool)> {
    let script: PathBuf = dir.join("inspect.py");
    std::fs::write(&script, INSPECT_SCRIPT).expect("write inspect script");
    let output: std::process::Output = Command::new(python_cmd())
        .arg(&script)
        .arg(marshal_path)
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!(
            "[real_marshal_reemit] inspect exited non-zero: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    let text: String = String::from_utf8(output.stdout).ok()?;
    let mut bits: Vec<u64> = Vec::new();
    let mut marker_ok: bool = false;
    for line in text.lines() {
        if let Some(hex) = line.strip_prefix("F ") {
            let raw: Vec<u8> = (0..hex.len())
                .step_by(2)
                .filter_map(|i: usize| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
                .collect();
            let array: [u8; 8] = raw.try_into().ok()?;
            bits.push(u64::from_le_bytes(array));
        } else if let Some(flag) = line.strip_prefix("MARKER ") {
            marker_ok = flag.trim() == "1";
        }
    }
    Some((bits, marker_ok))
}

fn collect(obj: &Object, strings: &mut Vec<String>, floats: &mut Vec<f64>) {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => strings.push(value.clone()),
        Object::Float(f) => floats.push(*f),
        Object::Complex { real, imag } => {
            floats.push(*real);
            floats.push(*imag);
        }
        Object::Tuple(items)
        | Object::List(items)
        | Object::Set(items)
        | Object::FrozenSet(items) => {
            for item in items {
                collect(item, strings, floats);
            }
        }
        Object::Dict(map) | Object::FrozenDict(map) => {
            for (key, value) in map {
                collect(key, strings, floats);
                collect(value, strings, floats);
            }
        }
        Object::Code(code) => {
            for constant in &code.consts {
                collect(constant, strings, floats);
            }
            for name in &code.names {
                collect(name, strings, floats);
            }
            collect(&code.name, strings, floats);
        }
        _ => {}
    }
}

fn decode_reemitted(body: &[u8], major: u8, minor: u8) -> (PycFile, usize) {
    let pyc: Vec<u8> = synthesize_pyc(body, major, minor).expect("synthesize pyc");
    let header_len: usize = PyVersion::new(major, minor).pyc_header_len();
    assert_eq!(
        &pyc[header_len..],
        body,
        "synthesized pyc must carry the marshalled body byte-for-byte after its header"
    );
    let decoded: PycFile = read_pyc(&pyc).expect("marshal reader must accept the synthesized pyc");
    assert_eq!(
        (decoded.header.version.major, decoded.header.version.minor),
        (major, minor),
        "the synthesized header magic must resolve to the exact interpreter version"
    );
    (decoded, header_len)
}

#[test]
fn synthesize_pyc_reemits_cpython_marshal_constants_byte_exact() {
    let dir: PathBuf = workdir("cpython");
    let Some(((major, minor), module_marshal, tuple_marshal)): Option<GeneratedMarshal> =
        run_generator(&dir)
    else {
        eprintln!(
            "[real_marshal_reemit] HONEST-PARTIAL: no usable CPython on PATH; synthesize_pyc re-emit not graded end-to-end this run"
        );
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    if magic_for(PyVersion::new(major, minor)).is_none() {
        eprintln!(
            "[real_marshal_reemit] HONEST-PARTIAL: CPython {major}.{minor} predates the supported pyc magic table; skipping"
        );
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let (module_pyc, _): (PycFile, usize) = decode_reemitted(&module_marshal, major, minor);
    assert!(
        matches!(module_pyc.code, Object::Code(_)),
        "a compiled module body must re-emit to a decodable code object"
    );
    let mut mod_strings: Vec<String> = Vec::new();
    let mut mod_floats: Vec<f64> = Vec::new();
    collect(&module_pyc.code, &mut mod_strings, &mut mod_floats);
    assert!(
        mod_strings.iter().any(|s: &String| s.contains(MARKER)),
        "the non-ascii string constant must survive re-emit with exact code points (no utf-8 double-encode or latin-1 split); recovered strings: {mod_strings:?}"
    );
    assert!(
        mod_floats
            .iter()
            .any(|f: &f64| f.to_bits() == (-0.0f64).to_bits()),
        "the folded -0.0 constant must retain its sign bit through re-emit"
    );
    assert!(
        mod_floats
            .iter()
            .any(|f: &f64| f.is_infinite() && f.is_sign_positive()),
        "the folded +inf constant must survive re-emit"
    );
    assert!(
        mod_floats
            .iter()
            .any(|f: &f64| f.is_infinite() && f.is_sign_negative()),
        "the folded -inf constant must survive re-emit"
    );

    let (tuple_pyc, _): (PycFile, usize) = decode_reemitted(&tuple_marshal, major, minor);
    let mut tup_strings: Vec<String> = Vec::new();
    let mut tup_floats: Vec<f64> = Vec::new();
    collect(&tuple_pyc.code, &mut tup_strings, &mut tup_floats);
    assert!(
        tup_strings.iter().any(|s: &String| s == MARKER),
        "the exact non-ascii marker must decode verbatim from the re-emitted data tuple: {tup_strings:?}"
    );
    assert!(
        tup_floats.iter().any(|f: &f64| f.is_nan()),
        "a marshalled nan must decode as nan after re-emit"
    );
    assert!(
        tup_floats
            .iter()
            .any(|f: &f64| f.to_bits() == (-0.0f64).to_bits()),
        "a marshalled -0.0 must decode with its sign bit intact after re-emit"
    );
    assert!(
        tup_floats
            .iter()
            .any(|f: &f64| f.is_infinite() && f.is_sign_positive())
            && tup_floats
                .iter()
                .any(|f: &f64| f.is_infinite() && f.is_sign_negative()),
        "both infinities must decode after re-emit"
    );

    let tuple_path: PathBuf = dir.join("tuple.marshal");
    if let Some((cpython_bits, cpython_marker)) = cpython_inspect(&dir, &tuple_path) {
        assert!(
            cpython_marker,
            "ground truth: CPython marshal.loads must see the marker on the same bytes"
        );
        let mut disrobe_bits: Vec<u64> = tup_floats.iter().map(|f: &f64| f.to_bits()).collect();
        let mut ground_bits: Vec<u64> = cpython_bits;
        disrobe_bits.sort_unstable();
        ground_bits.sort_unstable();
        assert_eq!(
            disrobe_bits, ground_bits,
            "every float bit pattern the marshal reader recovers from the re-emitted pyc must match CPython marshal.loads on the identical bytes"
        );
    } else {
        eprintln!(
            "[real_marshal_reemit] HONEST-PARTIAL: CPython cross-check inspect failed; disrobe-side decode still asserted"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}
