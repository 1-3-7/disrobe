#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_dotnet::interop::{
    CallingConvention, CharSet, InteropReport, StringMarshalling, interop_report,
};
use serde_json::Value;

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../corpus/dotnet/interop")
        .join(name)
}

fn sample() -> Vec<u8> {
    std::fs::read(corpus("Interop.dll")).expect("the interop sample is committed")
}

fn reference() -> Value {
    serde_json::from_slice(&std::fs::read(corpus("reference.json")).expect("reference"))
        .expect("reference JSON")
}

const fn char_set_name(char_set: CharSet) -> &'static str {
    match char_set {
        CharSet::NotSpecified => "None",
        CharSet::Ansi => "CharSetAnsi",
        CharSet::Unicode => "CharSetUnicode",
        CharSet::Auto => "CharSetMask",
    }
}

const fn calling_convention_name(convention: CallingConvention) -> &'static str {
    match convention {
        CallingConvention::NotSpecified | CallingConvention::Other(_) => "None",
        CallingConvention::Winapi => "CallingConventionWinApi",
        CallingConvention::Cdecl => "CallingConventionCDecl",
        CallingConvention::Stdcall => "CallingConventionStdCall",
        CallingConvention::Thiscall => "CallingConventionThisCall",
        CallingConvention::Fastcall => "CallingConventionFastCall",
    }
}

const fn toggle_name(
    value: Option<bool>,
    enable: &'static str,
    disable: &'static str,
) -> &'static str {
    match value {
        Some(true) => enable,
        Some(false) => disable,
        None => "None",
    }
}

fn mismatches(report: &InteropReport, reference: &Value) -> Vec<String> {
    let mut wrong: Vec<String> = Vec::new();
    let expected: &Vec<Value> = reference["pinvokes"].as_array().expect("pinvokes");
    let mut got: BTreeMap<String, Value> = BTreeMap::new();
    for pinvoke in &report.pinvokes {
        got.insert(
            pinvoke.method.clone(),
            serde_json::json!({
                "method": pinvoke.method,
                "token": pinvoke.token,
                "module": pinvoke.module,
                "entry_point": pinvoke.entry_point,
                "flags": pinvoke.flags,
                "char_set": char_set_name(pinvoke.char_set),
                "calling_convention": calling_convention_name(pinvoke.calling_convention),
                "set_last_error": pinvoke.set_last_error,
                "exact_spelling": pinvoke.exact_spelling,
                "best_fit": toggle_name(pinvoke.best_fit_mapping, "BestFitMappingEnable", "BestFitMappingDisable"),
                "throw_on_unmappable": toggle_name(
                    pinvoke.throw_on_unmappable_char,
                    "ThrowOnUnmappableCharEnable",
                    "ThrowOnUnmappableCharDisable"
                ),
                "preserve_sig": pinvoke.preserve_sig,
            }),
        );
    }
    if got.len() != expected.len() {
        wrong.push(format!(
            "{} P/Invoke methods, reference has {}",
            got.len(),
            expected.len()
        ));
    }
    for entry in expected {
        let method: &str = entry["method"].as_str().expect("method");
        match got.get(method) {
            Some(mine) if mine == entry => {}
            Some(mine) => wrong.push(format!("P/Invoke {method}: {mine} != {entry}")),
            None => wrong.push(format!("P/Invoke {method} missing")),
        }
    }

    let library: Vec<Value> = report
        .library_imports
        .iter()
        .map(|import| {
            let mut named: serde_json::Map<String, Value> = serde_json::Map::new();
            if let Some(entry) = &import.entry_point {
                named.insert("EntryPoint".to_owned(), Value::from(entry.clone()));
            }
            if import.set_last_error {
                named.insert("SetLastError".to_owned(), Value::from(true));
            }
            if let Some(marshalling) = import.string_marshalling {
                let code: i64 = match marshalling {
                    StringMarshalling::Custom => 0,
                    StringMarshalling::Utf8 => 1,
                    StringMarshalling::Utf16 => 2,
                    StringMarshalling::Other(other) => i64::from(other),
                };
                named.insert("StringMarshalling".to_owned(), Value::from(code));
            }
            serde_json::json!({
                "method": import.method,
                "token": import.token,
                "library": import.library,
                "named": named,
            })
        })
        .collect();
    if Value::Array(library.clone()) != reference["library_imports"] {
        wrong.push(format!(
            "LibraryImport: {library:?} != {}",
            reference["library_imports"]
        ));
    }

    let callable: Vec<Value> = report
        .native_callable
        .iter()
        .map(|export| {
            let mut named: serde_json::Map<String, Value> = serde_json::Map::new();
            if let Some(entry) = &export.entry_point {
                named.insert("EntryPoint".to_owned(), Value::from(entry.clone()));
            }
            if !export.calling_conventions.is_empty() {
                named.insert(
                    "CallConvs".to_owned(),
                    Value::from(export.calling_conventions.clone()),
                );
            }
            serde_json::json!({ "method": export.method, "token": export.token, "named": named })
        })
        .collect();
    let expected_callable: Vec<Value> = reference["native_callable"]
        .as_array()
        .expect("native_callable")
        .iter()
        .map(|entry: &Value| {
            let mut entry: Value = entry.clone();
            if let Some(list) = entry
                .get_mut("named")
                .and_then(|named: &mut Value| named.get_mut("CallConvs"))
                .and_then(Value::as_array_mut)
            {
                for item in list {
                    let short: String = item
                        .as_str()
                        .expect("type name")
                        .split(',')
                        .next()
                        .expect("name")
                        .trim()
                        .to_owned();
                    *item = Value::from(short);
                }
            }
            entry
        })
        .collect();
    if callable != expected_callable {
        wrong.push(format!(
            "UnmanagedCallersOnly: {callable:?} != {expected_callable:?}"
        ));
    }

    let com: Vec<Value> = report
        .com_imports
        .iter()
        .map(|import| {
            serde_json::json!({
                "type": import.type_name,
                "token": import.token,
                "guid": import.guid,
                "is_interface": import.interface,
            })
        })
        .collect();
    if Value::Array(com.clone()) != reference["com_imports"] {
        wrong.push(format!(
            "ComImport: {com:?} != {}",
            reference["com_imports"]
        ));
    }
    wrong
}

#[test]
fn interop_boundaries_match_system_reflection_metadata() {
    let report: InteropReport = interop_report(&sample()).expect("the sample parses");
    let wrong: Vec<String> = mismatches(&report, &reference());
    assert!(wrong.is_empty(), "{wrong:#?}");
    assert!(report.problems.is_empty(), "{:?}", report.problems);
    assert_eq!(report.modules.get("kernel32.dll"), Some(&4));
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    let at: usize = bytes
        .windows(from.len())
        .position(|window: &[u8]| window == from)
        .expect("pattern present");
    bytes[at..at + to.len()].copy_from_slice(to);
}

#[test]
fn changed_interop_metadata_is_caught_by_the_grader() {
    let reference: Value = reference();
    for (what, from, to) in [
        (
            "import name",
            b"GetModuleHandleA\0".as_slice(),
            b"GetModuleHandleB\0".as_slice(),
        ),
        (
            "module name",
            b"msvcrt.dll\0".as_slice(),
            b"msvcrx.dll\0".as_slice(),
        ),
        ("COM GUID", b"6D5140C1".as_slice(), b"6D5140C2".as_slice()),
        (
            "export name",
            b"disrobe_add".as_slice(),
            b"disrobe_sub".as_slice(),
        ),
    ] {
        let mut bytes: Vec<u8> = sample();
        replace_once(&mut bytes, from, to);
        let report: InteropReport = interop_report(&bytes).expect("still parses");
        assert!(
            !mismatches(&report, &reference).is_empty(),
            "a changed {what} must not pass the grader"
        );
    }
}

#[test]
fn corrupted_interop_metadata_gives_a_report_or_a_typed_error() {
    let original: Vec<u8> = sample();
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for round in 0..400 {
        let mut bytes: Vec<u8> = original.clone();
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let flips: u64 = 1 + state % 12;
        for flip in 0..flips {
            let at: usize =
                ((state.rotate_left(flip as u32 * 5) >> 3) % bytes.len() as u64) as usize;
            bytes[at] = (state >> (flip % 8 * 8)) as u8;
        }
        if round % 7 == 0 {
            bytes.truncate((state % bytes.len() as u64) as usize);
        }
        let _ = interop_report(&bytes);
    }
}
