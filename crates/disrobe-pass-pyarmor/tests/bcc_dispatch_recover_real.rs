#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::path::PathBuf;
use std::process::Command;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_pyarmor::{
    BccArch, PyAbi, RecoverOptions, RecoveredBody, UnpackOptions, link_bcc_from_unpack,
    recover_bcc_arith, unpack_wrapper_text_with_options,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, load};

fn corpus_default_dir() -> Option<PathBuf> {
    let dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()?
        .parent()?
        .join("corpus/python/pyarmor/v9-bcc/default");
    dir.is_dir().then_some(dir)
}

fn python() -> Option<String> {
    for candidate in ["python", "python3", "py"] {
        if Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
        {
            return Some(candidate.to_owned());
        }
    }
    None
}

fn text_section(blob: &[u8]) -> Option<(u64, Vec<u8>)> {
    const SHF_EXECINSTR: u64 = 0x4;
    if blob.len() < 64 || blob[..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    let shoff: usize =
        usize::try_from(u64::from_le_bytes(blob[0x28..0x30].try_into().ok()?)).ok()?;
    let shentsize: usize = usize::from(u16::from_le_bytes(blob[0x3a..0x3c].try_into().ok()?));
    let shnum: usize = usize::from(u16::from_le_bytes(blob[0x3c..0x3e].try_into().ok()?));
    let mut best: Option<(u64, Vec<u8>)> = None;
    for index in 0..shnum {
        let base: usize = shoff.checked_add(index.checked_mul(shentsize)?)?;
        if base
            .checked_add(64)
            .is_none_or(|end: usize| end > blob.len())
        {
            break;
        }
        let flags: u64 = u64::from_le_bytes(blob[base + 8..base + 16].try_into().ok()?);
        let addr: u64 = u64::from_le_bytes(blob[base + 16..base + 24].try_into().ok()?);
        let off: usize = usize::try_from(u64::from_le_bytes(
            blob[base + 24..base + 32].try_into().ok()?,
        ))
        .ok()?;
        let sz: usize = usize::try_from(u64::from_le_bytes(
            blob[base + 32..base + 40].try_into().ok()?,
        ))
        .ok()?;
        if flags & SHF_EXECINSTR == 0 || sz == 0 {
            continue;
        }
        let section: &[u8] = off.checked_add(sz).and_then(|e: usize| blob.get(off..e))?;
        if best
            .as_ref()
            .is_none_or(|(_, b): &(u64, Vec<u8>)| section.len() > b.len())
        {
            best = Some((addr, section.to_vec()));
        }
    }
    best
}

fn code_name(co: &CodeObject) -> String {
    match &co.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.clone(),
        _ => String::new(),
    }
}

fn int_of(obj: &Object) -> Option<i128> {
    match obj {
        Object::Int(value) => Some(i128::from(*value)),
        Object::Long(big) => {
            let mut magnitude: i128 = 0;
            for (index, digit) in big.digits.iter().enumerate() {
                let shift: u32 = u32::try_from(index).ok()?.checked_mul(15)?;
                let term: i128 = i128::from(*digit).checked_shl(shift)?;
                magnitude = magnitude.checked_add(term)?;
            }
            Some(magnitude * i128::from(big.sign))
        }
        _ => None,
    }
}

fn const_tuple(co: &CodeObject) -> Vec<Option<i128>> {
    match co.consts.get(2) {
        Some(Object::Tuple(items)) => items.iter().map(int_of).collect(),
        _ => Vec::new(),
    }
}

fn find_function<'a>(module: &'a CodeObject, name: &str) -> Option<&'a CodeObject> {
    module.consts.iter().find_map(|c: &'a Object| match c {
        Object::Code(child) if code_name(child) == name => Some(child.as_ref()),
        _ => None,
    })
}

fn param_names(co: &CodeObject) -> Vec<String> {
    let count: usize = usize::try_from(co.argcount.max(0)).unwrap_or(0);
    co.varnames
        .iter()
        .take(count)
        .filter_map(|v: &Object| match v {
            Object::String { value, .. }
            | Object::Unicode { value, .. }
            | Object::ShortAscii { value, .. } => Some(value.clone()),
            _ => None,
        })
        .collect()
}

struct Prepared {
    module: CodeObject,
    text_addr: u64,
    text: Vec<u8>,
    map: disrobe_pass_pyarmor::BccLinkOutput,
}

fn prepare() -> Option<Prepared> {
    let dir: PathBuf = corpus_default_dir()?;
    let wrapper_path: PathBuf = dir.join("known_plaintext.py");
    let wrapper_text: String = std::fs::read_to_string(&wrapper_path).ok()?;
    let opts: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let out = unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &opts).ok()?;
    let map = link_bcc_from_unpack(&out, &wrapper_text, &wrapper_path).ok()?;
    let blob: &Vec<u8> = &out.bcc_blobs.first()?.bytes;
    let (text_addr, text): (u64, Vec<u8>) = text_section(blob)?;
    let pyc: &Vec<u8> = out.pyc.as_ref()?;
    let pv: PyVersion = out.py_version.unwrap_or_else(|| PyVersion::new(3, 12));
    let object: Object = load(pyc.get(16..)?, pv).ok()?;
    let Object::Code(module): Object = object else {
        return None;
    };
    Some(Prepared {
        module: *module,
        text_addr,
        text,
        map,
    })
}

fn recover_named(prep: &Prepared, qualname: &str) -> Option<RecoveredBody> {
    let record: &disrobe_pass_pyarmor::FunctionRecord = prep
        .map
        .map
        .native_records()
        .find(|r: &&disrobe_pass_pyarmor::FunctionRecord| r.source.qualname == qualname)?;
    let reference: &disrobe_pass_pyarmor::NativeRef = record.native.as_ref()?;
    let rel: usize = usize::try_from(reference.offset.saturating_sub(prep.text_addr)).ok()?;
    let size: usize = usize::try_from(reference.size)
        .unwrap_or(0)
        .min(prep.text.len().saturating_sub(rel));
    if size == 0 {
        return None;
    }
    let code: &[u8] = &prep.text[rel..rel + size];
    let function: &CodeObject = find_function(&prep.module, qualname)?;
    let consts: Vec<Option<i128>> = const_tuple(function);
    let mut options: RecoverOptions = RecoverOptions::new(
        qualname.to_owned(),
        PyAbi::from_arch(BccArch::WinX64).expect("Windows x64 must have a BCC ABI"),
        record.signature.argcount as usize,
    );
    let names: Vec<String> = param_names(function);
    options.param_names = if names.len() == record.signature.argcount as usize {
        names
    } else {
        record
            .signature
            .parameters
            .iter()
            .map(|p: &disrobe_pass_pyarmor::Parameter| p.name.clone())
            .collect()
    };
    Some(recover_bcc_arith(code, reference.offset, &options, &consts))
}

fn behavioral_check(py: &str, name: &str, arity: usize, reference_body: &str, recovered_def: &str) {
    let call_args: String = (0..arity)
        .map(|i: usize| format!("combo[{i}]"))
        .collect::<Vec<String>>()
        .join(", ");
    let script: String = format!(
        "import itertools, sys\n\
         def reference(a, b, c):\n{reference_body}\n\
         {recovered_def}\n\
         vals = [-7, -3, -1, 0, 1, 2, 5, 11, 123, -456, 1000]\n\
         for combo in itertools.product(vals, repeat=3):\n\
         \x20   want = reference(combo[0], combo[1], combo[2])\n\
         \x20   got = {name}({call_args})\n\
         \x20   if want != got:\n\
         \x20       print('MISMATCH', combo, want, got); sys.exit(1)\n\
         print('OK')\n",
    );
    let scratch: ScratchDir =
        ScratchDir::create(&format!("pyarmor-bcc-dispatch-{name}")).expect("scratch");
    let script_path: PathBuf = scratch.path().join(format!("check_{name}.py"));
    std::fs::write(&script_path, script).expect("write");
    let out: std::process::Output = Command::new(py)
        .arg(&script_path)
        .output()
        .expect("run python");
    let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("OK"),
        "behavioral equivalence FAILED for {name}: {stdout}\nstderr: {}\nrecovered:\n{recovered_def}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn straight_line_bcc_bodies_recover_and_match_cpython() {
    if !cfg!(target_arch = "x86_64") {
        eprintln!("skipping: BCC recovery targets x86-64");
        return;
    }
    let Some(prep): Option<Prepared> = prepare() else {
        eprintln!("v9-bcc corpus absent or undecryptable; skipping");
        return;
    };

    let mix_add: RecoveredBody = recover_named(&prep, "mix_add").expect("mix_add native record");
    println!(
        "mix_add: {}/{} dispatcher sites, python={:?}",
        mix_add.recognized_call_sites, mix_add.total_call_sites, mix_add.recovered_python
    );
    assert_eq!(
        mix_add.total_call_sites, 4,
        "mix_add issues four binary ops"
    );
    assert_eq!(mix_add.recognized_call_sites, 4, "all four resolve");
    assert!(
        (mix_add.coverage() - 1.0).abs() < f64::EPSILON,
        "mix_add resolves every dispatcher site"
    );
    let mix_symbols: Vec<&str> = mix_add
        .calls
        .iter()
        .filter_map(|c: &disrobe_pass_pyarmor::RecognizedCall| c.symbol.as_deref())
        .collect();
    assert_eq!(
        mix_symbols,
        vec![
            "PyNumber_Add",
            "PyNumber_Multiply",
            "PyNumber_Xor",
            "PyNumber_Subtract"
        ],
        "mix_add op sequence must match (a + b) * 3 - (a ^ b)"
    );
    let mix_def: String = mix_add
        .recovered_python
        .clone()
        .expect("mix_add recovers a def");

    let poly: RecoveredBody = recover_named(&prep, "poly").expect("poly native record");
    println!(
        "poly: {}/{} dispatcher sites, python={:?}",
        poly.recognized_call_sites, poly.total_call_sites, poly.recovered_python
    );
    assert!(poly.total_call_sites >= 6, "poly issues several binary ops");
    assert_eq!(
        poly.recognized_call_sites, poly.total_call_sites,
        "poly resolves every dispatcher site"
    );
    let poly_def: String = poly.recovered_python.expect("poly recovers a def");

    let clamp: RecoveredBody = recover_named(&prep, "clamp").expect("clamp native record");
    println!(
        "clamp: {}/{} dispatcher sites, python={:?}, notes={:?}",
        clamp.recognized_call_sites, clamp.total_call_sites, clamp.recovered_python, clamp.notes
    );
    let clamp_def: String = clamp
        .recovered_python
        .clone()
        .expect("clamp recovers its guarded result-local body from the real BCC ABI");
    assert_eq!(
        clamp_def.matches("if result").count(),
        2,
        "clamp recovers exactly two guards: {clamp_def}"
    );
    assert!(
        clamp_def.contains("result < ")
            && clamp_def.contains("result > ")
            && clamp_def.trim_end().ends_with("return result"),
        "clamp recovers the two-guard result-local shape (< then >): {clamp_def}"
    );
    let clamp_symbols: Vec<&str> = clamp
        .calls
        .iter()
        .filter_map(|c: &disrobe_pass_pyarmor::RecognizedCall| c.symbol.as_deref())
        .collect();
    assert!(
        clamp_symbols.contains(&"PyObject_RichCompare"),
        "clamp's compare dispatch (slot 0x40) is recognized, not walled: {clamp_symbols:?}"
    );
    assert!(
        clamp_symbols.contains(&"PyObject_IsTrue"),
        "clamp's truth-test dispatch (slot 0x198) is recognized, not walled: {clamp_symbols:?}"
    );
    assert!(
        !clamp
            .notes
            .iter()
            .any(|note: &String| note.contains("unmodeled runtime dispatch slot")),
        "clamp no longer degrades on an unmodeled dispatch slot: {:?}",
        clamp.notes
    );
    let collapse_note: Option<&String> = clamp
        .notes
        .iter()
        .find(|note: &&String| note.contains("refcount-increment fast-path guards"));
    assert!(
        collapse_note.is_some(),
        "the refcount fast-path normalizer fires on the real clamp body: {:?}",
        clamp.notes
    );
    let collapsed: usize = collapse_note
        .and_then(|note: &String| note.split_whitespace().nth(1))
        .and_then(|token: &str| token.parse::<usize>().ok())
        .unwrap_or(0);
    assert!(
        collapsed >= 1,
        "at least one refcount-increment diamond collapses in the real clamp body: {collapsed}"
    );

    let main: RecoveredBody = recover_named(&prep, "main").expect("main native record");
    assert!(
        main.recovered_python.is_none(),
        "main calls helpers and loops; it must degrade honestly"
    );

    let Some(py): Option<String> = python() else {
        eprintln!(
            "recovery asserted structurally; no python interpreter to confirm behavior, skipping differential"
        );
        return;
    };
    let mix_name: &str = mix_def
        .lines()
        .next()
        .and_then(|l: &str| l.strip_prefix("def "))
        .and_then(|l: &str| l.split('(').next())
        .unwrap_or("mix_add");
    behavioral_check(
        &py,
        mix_name,
        2,
        "    return (a + b) * 3 - (a ^ b)",
        &mix_def,
    );
    let poly_name: &str = poly_def
        .lines()
        .next()
        .and_then(|l: &str| l.strip_prefix("def "))
        .and_then(|l: &str| l.split('(').next())
        .unwrap_or("poly");
    behavioral_check(
        &py,
        poly_name,
        1,
        "    return a * a * a + 2 * a * a - 5 * a + 7",
        &poly_def,
    );
    let clamp_name: &str = clamp_def
        .lines()
        .next()
        .and_then(|l: &str| l.strip_prefix("def "))
        .and_then(|l: &str| l.split('(').next())
        .unwrap_or("clamp");
    behavioral_check(
        &py,
        clamp_name,
        3,
        "    result = a\n    if result < b:\n        result = b\n    if result > c:\n        result = c\n    return result",
        &clamp_def,
    );
    println!(
        "mix_add, poly, and clamp recovered and behaviorally matched real CPython 3.12 semantics"
    );
}
