#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_dataforensics::crash::{
    CrashFormat, CrashLimits, CrashReport, FaultKind, Location, inspect,
};
use disrobe_tool_process::{CommandSpec, Completion, Execution};
use serde_json::Value;

struct Generated {
    dir: ScratchDir,
    truth: Value,
}

fn exited_cleanly(execution: &Execution) -> bool {
    matches!(execution.completion, Completion::Exited(status) if status.success())
}

fn probe(program: &str, args: &[&str]) -> bool {
    CommandSpec::new(program, Duration::from_secs(30))
        .args(args.iter().copied())
        .run()
        .is_ok_and(|execution: Execution| exited_cleanly(&execution))
}

fn tool(variable: &str, candidates: &[&str], args: &[&str], purpose: &str) -> String {
    if let Ok(explicit) = std::env::var(variable)
        && probe(&explicit, args)
    {
        return explicit;
    }
    candidates
        .iter()
        .find(|candidate: &&&str| probe(candidate, args))
        .map_or_else(
            || panic!("{purpose}; point {variable} at one"),
            |found: &&str| (*found).to_owned(),
        )
}

fn python() -> String {
    tool(
        "DISROBE_PYTHON",
        &["python", "python3", "py"],
        &["-c", "import ctypes, struct"],
        "the crash grader needs CPython 3 to write its reference records",
    )
}

fn readelf() -> String {
    tool(
        "DISROBE_READELF",
        &["readelf", "llvm-readelf"],
        &["--version"],
        "the core grader validates its authored cores with GNU readelf or llvm-readelf",
    )
}

fn generate(script: &str, label: &str) -> Generated {
    let dir: ScratchDir = ScratchDir::create(label).expect("scratch");
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/support")
        .join(script);
    let execution: Execution = CommandSpec::new(python(), Duration::from_mins(2))
        .arg(path.as_os_str())
        .arg(dir.path().as_os_str())
        .run()
        .expect("run the generator");
    assert!(exited_cleanly(&execution), "{script} failed: {execution:?}");
    let truth: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("truth.json")).expect("truth"))
            .expect("truth JSON");
    Generated { dir, truth }
}

fn cores() -> &'static Generated {
    static CORES: OnceLock<Generated> = OnceLock::new();
    CORES.get_or_init(|| generate("make_cores.py", "crash-cores"))
}

fn core_names() -> Vec<String> {
    cores()
        .truth
        .as_object()
        .expect("truth object")
        .keys()
        .cloned()
        .collect()
}

fn core_bytes(name: &str) -> Vec<u8> {
    std::fs::read(cores().dir.path().join(format!("{name}.core"))).expect("generated core")
}

fn report(bytes: &[u8]) -> CrashReport {
    inspect(bytes, &CrashLimits::default()).expect("crash record parses")
}

fn number(value: &Value) -> u64 {
    value.as_u64().expect("number")
}

fn location(value: &Value) -> Option<Location> {
    value.as_object().map(|object| Location {
        module: object["module"].as_str().expect("module").to_owned(),
        offset: number(&object["offset"]),
    })
}

fn optional_number(value: &Value) -> Option<u64> {
    value.as_u64()
}

fn check_core(name: &str, report: &CrashReport) -> Vec<String> {
    let truth: &Value = &cores().truth[name];
    let mut wrong: Vec<String> = Vec::new();
    let mut expect = |what: &str, ok: bool| {
        if !ok {
            wrong.push(format!("{name}: {what}"));
        }
    };
    expect("format", report.format == CrashFormat::ElfCore);
    expect(
        "machine",
        u64::from(report.machine) == number(&truth["machine"]),
    );
    expect(
        "pointer width",
        u64::from(report.pointer_bytes) * 8 == number(&truth["bits"]),
    );
    expect(
        "byte order",
        Some(report.big_endian) == truth["big_endian"].as_bool(),
    );

    let process: &Value = &truth["process"];
    expect(
        "pid",
        report.process.pid.map(u64::from) == process["pid"].as_u64(),
    );
    expect(
        "parent pid",
        report.process.parent_pid.map(u64::from) == process["ppid"].as_u64(),
    );
    expect(
        "uid",
        report.process.uid.map(u64::from) == process["uid"].as_u64(),
    );
    expect(
        "gid",
        report.process.gid.map(u64::from) == process["gid"].as_u64(),
    );
    expect(
        "name",
        report.process.name.as_deref() == process["name"].as_str(),
    );
    expect(
        "command line",
        report.process.command_line.as_deref() == process["command_line"].as_str(),
    );
    expect(
        "executable",
        report.process.executable.as_deref() == process["executable"].as_str(),
    );

    let decoded: bool = truth["decoded"].as_bool().expect("decoded");
    let threads: &Vec<Value> = truth["threads"].as_array().expect("threads");
    expect("thread count", report.threads.len() == threads.len());
    for (thread, expected) in report.threads.iter().zip(threads) {
        let id: u64 = number(&expected["id"]);
        expect("thread id", u64::from(thread.id) == id);
        expect(
            &format!("thread {id} crashed flag"),
            Some(thread.crashed) == expected["crashed"].as_bool(),
        );
        if !decoded {
            expect(
                &format!("thread {id} registers are not guessed"),
                thread.registers.is_empty() && thread.instruction_pointer.is_none(),
            );
            continue;
        }
        expect(
            &format!("thread {id} instruction pointer"),
            thread.instruction_pointer == optional_number(&expected["ip"]),
        );
        expect(
            &format!("thread {id} stack pointer"),
            thread.stack_pointer == optional_number(&expected["sp"]),
        );
        expect(
            &format!("thread {id} frame pointer"),
            thread.frame_pointer == optional_number(&expected["fp"]),
        );
        expect(
            &format!("thread {id} location"),
            thread.location == location(&expected["location"]),
        );
        let registers: Vec<(String, u64)> = expected["registers"]
            .as_array()
            .expect("registers")
            .iter()
            .map(|pair: &Value| (pair[0].as_str().expect("name").to_owned(), number(&pair[1])))
            .collect();
        let got: Vec<(String, u64)> = thread
            .registers
            .iter()
            .map(|register| (register.name.to_owned(), register.value))
            .collect();
        expect(&format!("thread {id} registers"), got == registers);
        let scan: Vec<(u64, u64, Option<Location>)> = expected["scan"]
            .as_array()
            .expect("scan")
            .iter()
            .map(|word: &Value| {
                (
                    number(&word["address"]),
                    number(&word["value"]),
                    location(word),
                )
            })
            .collect();
        let got_scan: Vec<(u64, u64, Option<Location>)> = thread
            .stack_scan
            .iter()
            .map(|word| (word.address, word.value, Some(word.location.clone())))
            .collect();
        expect(&format!("thread {id} stack scan"), got_scan == scan);
    }
    if !decoded {
        expect(
            "undecoded registers are named as a problem",
            report
                .problems
                .iter()
                .any(|problem: &String| problem.contains("are not decoded")),
        );
    }

    let fault: &Value = &truth["fault"];
    match &report.fault {
        None => expect("fault present", false),
        Some(got) => {
            expect("fault kind", got.kind == FaultKind::Signal);
            expect("signal", u64::from(got.code) == number(&fault["signal"]));
            expect("signal name", got.name == fault["name"].as_str());
            expect("signal reason", got.reason == fault["reason"].as_str());
            expect(
                "fault thread",
                got.thread_id.map(u64::from) == fault["thread"].as_u64(),
            );
            expect(
                "instruction address",
                got.instruction_address == optional_number(&fault["instruction_address"]),
            );
            expect(
                "instruction location",
                got.instruction_location == location(&fault["instruction_location"]),
            );
            expect(
                "data address",
                got.data_address == optional_number(&fault["data_address"]),
            );
            expect(
                "data location",
                got.data_location == location(&fault["data_location"]),
            );
            let sender: Option<(i64, u64)> = fault["sender"]
                .as_object()
                .map(|object| (object["pid"].as_i64().expect("pid"), number(&object["uid"])));
            expect(
                "sender",
                got.sender
                    .map(|sender| (i64::from(sender.pid), u64::from(sender.uid)))
                    == sender,
            );
        }
    }

    let modules: &Vec<Value> = truth["modules"].as_array().expect("modules");
    expect("module count", report.modules.len() == modules.len());
    for (module, expected) in report.modules.iter().zip(modules) {
        expect(
            "module path",
            Some(module.path.as_str()) == expected["path"].as_str(),
        );
        expect("module base", module.base == number(&expected["base"]));
        expect("module size", module.size == number(&expected["size"]));
        expect(
            &format!("{} build id", module.path),
            module.build_id.as_deref() == expected["build_id"].as_str(),
        );
    }

    let auxv: Vec<(u64, u64)> = truth["auxv"]
        .as_array()
        .expect("auxv")
        .iter()
        .map(|pair: &Value| (number(&pair[0]), number(&pair[1])))
        .collect();
    let got_auxv: Vec<(u64, u64)> = report
        .auxv
        .iter()
        .map(|entry| (entry.key, entry.value))
        .collect();
    expect("auxv", got_auxv == auxv);
    for (key, text) in truth["strings"].as_object().expect("strings") {
        let key: u64 = key.parse().expect("aux key");
        expect(
            &format!("auxv string {key}"),
            report
                .auxv
                .iter()
                .find(|entry| entry.key == key)
                .and_then(|entry| entry.string.as_deref())
                == text.as_str(),
        );
    }

    let notes: BTreeMap<String, u64> = truth["notes"]
        .as_object()
        .expect("notes")
        .iter()
        .map(|(label, count)| (label.clone(), number(count)))
        .collect();
    expect("note counts", report.records == notes);
    expect(
        "segments",
        report.memory.segments == number(&truth["loads"]),
    );
    expect(
        "captured bytes",
        report.memory.captured_bytes == number(&truth["captured"]),
    );
    expect(
        "executable segments",
        report.memory.executable_segments == number(&truth["executable"]),
    );
    wrong
}

#[test]
fn authored_cores_read_the_same_under_readelf() {
    let readelf: String = readelf();
    for name in core_names() {
        let truth: &Value = &cores().truth[&name];
        let path: PathBuf = cores().dir.path().join(format!("{name}.core"));
        let run = |flag: &str| -> String {
            let execution: Execution = CommandSpec::new(readelf.as_str(), Duration::from_mins(1))
                .args([flag, "-W"])
                .arg(path.as_os_str())
                .run()
                .expect("run readelf");
            assert!(
                exited_cleanly(&execution),
                "readelf {flag} {name}: {execution:?}"
            );
            let stdout = execution.stdout.captured().expect("readelf output");
            assert!(!stdout.truncated, "readelf {flag} {name}: output truncated");
            String::from_utf8_lossy(&stdout.bytes).into_owned()
        };
        let notes: String = run("-n");
        for (label, count) in truth["notes"].as_object().expect("notes") {
            let shown: &str = if label == "NT_PRFPREG" {
                "NT_FPREGSET"
            } else {
                label
            };
            let found: usize = notes
                .lines()
                .filter(|line: &&str| line.contains(&format!("{shown} (")))
                .count();
            assert_eq!(found as u64, number(count), "{name}: readelf {label} count");
        }
        let lines: Vec<&str> = notes.lines().map(str::trim).collect();
        let mut listed: Vec<(u64, u64, u64, String)> = Vec::new();
        for pair in lines.windows(2) {
            let fields: Vec<&str> = pair[0].split_whitespace().collect();
            if fields.len() == 3 && fields.iter().all(|field: &&str| field.starts_with("0x")) {
                let parse = |text: &str| u64::from_str_radix(&text[2..], 16).expect("hex");
                listed.push((
                    parse(fields[0]),
                    parse(fields[1]),
                    parse(fields[2]),
                    pair[1].to_owned(),
                ));
            }
        }
        let mappings: Vec<(u64, u64, u64, String)> = truth["mappings"]
            .as_array()
            .expect("mappings")
            .iter()
            .map(|entry: &Value| {
                (
                    number(&entry[0]),
                    number(&entry[1]),
                    number(&entry[2]),
                    entry[3].as_str().expect("path").to_owned(),
                )
            })
            .collect();
        assert_eq!(
            listed, mappings,
            "{name}: readelf NT_FILE table; readelf -n printed:\n{notes}"
        );
        let headers: String = run("-l");
        let loads: usize = headers
            .lines()
            .filter(|line: &&str| line.trim_start().starts_with("LOAD "))
            .count();
        assert_eq!(
            loads as u64,
            number(&truth["loads"]),
            "{name}: readelf PT_LOAD count"
        );
    }
}

#[test]
fn every_core_report_matches_what_the_generator_wrote() {
    let mut wrong: Vec<String> = Vec::new();
    for name in core_names() {
        let bytes: Vec<u8> = core_bytes(&name);
        wrong.extend(check_core(&name, &report(&bytes)));
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

fn replace_once(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    let at: usize = bytes
        .windows(from.len())
        .position(|window: &[u8]| window == from)
        .expect("pattern present");
    bytes[at..at + to.len()].copy_from_slice(to);
}

#[test]
fn changed_core_bytes_are_caught_by_the_grader() {
    let truth: &Value = &cores().truth["x86_64"];
    let ip: u64 = number(&truth["threads"][0]["ip"]);
    let build_id: Vec<u8> = (0x10..0x24).collect();
    let mutations: [(&str, Vec<u8>, Vec<u8>); 3] = [
        (
            "register",
            ip.to_le_bytes().to_vec(),
            (ip + 4).to_le_bytes().to_vec(),
        ),
        (
            "mapped path",
            b"/usr/bin/crashme\0".to_vec(),
            b"/usr/bin/crashmf\0".to_vec(),
        ),
        ("build id", build_id, vec![0u8; 20]),
    ];
    for (what, from, to) in mutations {
        let mut bytes: Vec<u8> = core_bytes("x86_64");
        replace_once(&mut bytes, &from, &to);
        let mutated: CrashReport = report(&bytes);
        assert!(
            !check_core("x86_64", &mutated).is_empty(),
            "a changed {what} must not pass the grader"
        );
    }
}

const fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn corrupt_and_inspect(original: &[u8], seed: u64, rounds: usize) {
    let mut state: u64 = seed;
    let tight: CrashLimits = CrashLimits {
        threads: 2,
        modules: 1,
        segments: 4,
        notes: 6,
        auxv: 3,
        stack_scan_bytes: 64,
        stack_candidates: 1,
    };
    for round in 0..rounds {
        let mut bytes: Vec<u8> = original.to_vec();
        let flips: u64 = 1 + xorshift(&mut state) % 16;
        for _ in 0..flips {
            let at: usize = (xorshift(&mut state) % bytes.len() as u64) as usize;
            bytes[at] = xorshift(&mut state) as u8;
        }
        if round % 5 == 0 {
            let keep: usize = (xorshift(&mut state) % bytes.len() as u64) as usize;
            bytes.truncate(keep.max(4));
        }
        let limits: CrashLimits = if round % 3 == 0 {
            tight
        } else {
            CrashLimits::default()
        };
        let outcome = inspect(&bytes, &limits);
        if let Ok(report) = outcome {
            assert!(report.threads.len() <= limits.threads);
            assert!(report.modules.len() <= limits.modules);
            for thread in &report.threads {
                assert!(thread.stack_scan.len() <= limits.stack_candidates);
            }
        }
    }
}

#[test]
fn corrupted_cores_give_a_report_or_a_typed_error() {
    for (index, name) in core_names().iter().enumerate() {
        corrupt_and_inspect(&core_bytes(name), 0x9E37_79B9_7F4A_7C15 ^ index as u64, 100);
    }
    let mut not_core: Vec<u8> = core_bytes("x86_64");
    not_core[16] = 2;
    assert!(inspect(&not_core, &CrashLimits::default()).is_err());
    assert!(inspect(b"not a crash record", &CrashLimits::default()).is_err());
}

#[cfg(windows)]
mod windows_minidumps {
    use super::*;
    use disrobe_dataforensics::crash::ThreadReport;

    fn dumps() -> &'static Generated {
        static DUMPS: OnceLock<Generated> = OnceLock::new();
        DUMPS.get_or_init(|| generate("make_minidump.py", "crash-minidumps"))
    }

    fn dump(name: &str) -> Vec<u8> {
        std::fs::read(dumps().dir.path().join(name)).expect("written minidump")
    }

    const fn same_path(a: &str, b: &str) -> bool {
        a.eq_ignore_ascii_case(b)
    }

    fn check_exception_dump(report: &CrashReport) -> Vec<String> {
        let truth: &Value = &dumps().truth;
        let mut wrong: Vec<String> = Vec::new();
        let mut expect = |what: &str, ok: bool| {
            if !ok {
                wrong.push(what.to_owned());
            }
        };
        expect("format", report.format == CrashFormat::Minidump);
        expect("pointer width", report.pointer_bytes == 8);
        let os: &Value = &truth["os"];
        match &report.system {
            None => expect("system info", false),
            Some(system) => {
                expect("platform", system.platform == "windows-nt");
                expect("major", u64::from(system.major) == number(&os["major"]));
                expect("minor", u64::from(system.minor) == number(&os["minor"]));
                expect("build", u64::from(system.build) == number(&os["build"]));
                expect(
                    "processors",
                    u64::from(system.processors) == number(&os["processors"]) & 0xFF,
                );
            }
        }
        expect(
            "pid",
            report.process.pid.map(u64::from) == truth["pid"].as_u64(),
        );
        expect(
            "start time",
            report.process.start_time_unix.map(u64::from) == truth["start_time_unix"].as_u64(),
        );

        let main: u64 = number(&truth["main_thread"]);
        let by_id: BTreeMap<u64, &ThreadReport> = report
            .threads
            .iter()
            .map(|thread: &ThreadReport| (u64::from(thread.id), thread))
            .collect();
        for (name, id) in truth["workers"].as_object().expect("workers") {
            let thread: Option<&&ThreadReport> = by_id.get(&number(id));
            expect(
                &format!("worker {name} named"),
                thread.and_then(|thread| thread.name.as_deref()) == Some(name.as_str()),
            );
        }
        let crashed: Vec<u64> = report
            .threads
            .iter()
            .filter(|thread| thread.crashed)
            .map(|thread| u64::from(thread.id))
            .collect();
        expect("only the faulting thread crashed", crashed == vec![main]);
        let fault: &Value = &truth["fault"];
        let python: &Value = &truth["python_dll"];
        let python_path: &str = python["path"].as_str().expect("python path");
        let fault_offset: u64 = number(&fault["offset"]);
        if let Some(thread) = by_id.get(&main) {
            for (name, value) in truth["markers"].as_object().expect("markers") {
                expect(
                    &format!("register {name}"),
                    thread
                        .registers
                        .iter()
                        .find(|register| register.name == name)
                        .map(|register| register.value)
                        == value.as_u64(),
                );
            }
            expect(
                "crashed instruction pointer",
                thread.instruction_pointer == fault["address"].as_u64(),
            );
            expect(
                "crashed stack pointer",
                thread.stack_pointer == truth["rsp"].as_u64(),
            );
            expect(
                "crashed location",
                thread.location.as_ref().is_some_and(|location| {
                    same_path(&location.module, python_path) && location.offset == fault_offset
                }),
            );
        } else {
            expect("faulting thread listed", false);
        }
        match &report.fault {
            None => expect("fault present", false),
            Some(got) => {
                expect("fault kind", got.kind == FaultKind::Exception);
                expect("code", u64::from(got.code) == number(&fault["code"]));
                expect("name", got.name == Some("EXCEPTION_ACCESS_VIOLATION"));
                expect(
                    "access",
                    got.access == Some(disrobe_dataforensics::crash::Access::Write),
                );
                expect(
                    "data address",
                    got.data_address == fault["data_address"].as_u64(),
                );
                expect(
                    "instruction address",
                    got.instruction_address == fault["address"].as_u64(),
                );
                expect(
                    "instruction location",
                    got.instruction_location.as_ref().is_some_and(|location| {
                        same_path(&location.module, python_path) && location.offset == fault_offset
                    }),
                );
                let parameters: Vec<u64> = fault["parameters"]
                    .as_array()
                    .expect("parameters")
                    .iter()
                    .map(number)
                    .collect();
                expect("parameters", got.parameters == parameters);
                expect("fault thread", got.thread_id.map(u64::from) == Some(main));
            }
        }

        let listed = |key: &str| -> Vec<(String, u64, u64)> {
            truth[key]
                .as_array()
                .expect("modules")
                .iter()
                .map(|module: &Value| {
                    (
                        module["path"].as_str().expect("path").to_owned(),
                        number(&module["base"]),
                        number(&module["size"]),
                    )
                })
                .collect()
        };
        let after: Vec<(String, u64, u64)> = listed("modules_after");
        let before: Vec<(String, u64, u64)> = listed("modules_before");
        for module in &report.modules {
            expect(
                &format!("module {} as the process listed it", module.path),
                after.iter().any(|(path, base, size)| {
                    same_path(path, &module.path) && *base == module.base && *size == module.size
                }),
            );
        }
        for (path, base, _) in &before {
            expect(
                &format!("module {path} present"),
                report.modules.iter().any(|module| module.base == *base),
            );
        }
        for (key, path) in [
            ("python", python_path),
            ("ntdll", truth["ntdll"].as_str().expect("ntdll")),
        ] {
            let expected: &Value = &truth["pdb"][key];
            let module = report
                .modules
                .iter()
                .find(|module| same_path(&module.path, path));
            expect(
                &format!("{key} pdb identity"),
                module
                    .and_then(|module| module.pdb.as_ref())
                    .is_some_and(|pdb| {
                        Some(pdb.id.as_str()) == expected["id"].as_str()
                            && Some(pdb.name.as_str()) == expected["pdb"].as_str()
                    }),
            );
            expect(
                &format!("{key} timestamp"),
                module.and_then(|module| module.timestamp).map(u64::from)
                    == expected["timestamp"].as_u64(),
            );
        }
        expect(
            "executable ranges listed",
            report.memory.executable_segments > 0,
        );
        wrong
    }

    #[test]
    fn windows_written_minidumps_match_the_process_that_wrote_them() {
        let exception: CrashReport = report(&dump("exception.dmp"));
        let wrong: Vec<String> = check_exception_dump(&exception);
        assert!(wrong.is_empty(), "{wrong:#?}");
        for thread in &exception.threads {
            let stack = thread.stack.expect("stack span");
            for word in &thread.stack_scan {
                assert!(
                    word.address >= stack.start && word.address < stack.start + stack.size,
                    "scan word outside the stack of thread {}",
                    thread.id
                );
                assert!(
                    exception
                        .modules
                        .iter()
                        .any(|module| module.path == word.location.module),
                );
            }
        }

        let plain: CrashReport = report(&dump("plain.dmp"));
        assert!(plain.fault.is_none());
        assert!(plain.threads.iter().all(|thread| !thread.crashed));
        let workers: Vec<u64> = dumps().truth["workers"]
            .as_object()
            .expect("workers")
            .values()
            .map(number)
            .collect();
        for id in workers {
            let thread = plain
                .threads
                .iter()
                .find(|thread| u64::from(thread.id) == id)
                .expect("worker in the plain dump");
            assert!(
                thread.location.is_some(),
                "a waiting worker's instruction pointer lies in a module"
            );
        }
    }

    #[test]
    fn changed_minidump_bytes_are_caught_by_the_grader() {
        let truth: &Value = &dumps().truth;
        let marker: u64 = number(&truth["markers"]["rbx"]);
        let mutations: [(&str, Vec<u8>, Vec<u8>); 2] = [
            (
                "exception code",
                0xC000_0005_u32.to_le_bytes().to_vec(),
                0xC000_001D_u32.to_le_bytes().to_vec(),
            ),
            (
                "context register",
                marker.to_le_bytes().to_vec(),
                (marker ^ 1).to_le_bytes().to_vec(),
            ),
        ];
        for (what, from, to) in mutations {
            let mut bytes: Vec<u8> = dump("exception.dmp");
            replace_once(&mut bytes, &from, &to);
            let mutated: CrashReport = report(&bytes);
            assert!(
                !check_exception_dump(&mutated).is_empty(),
                "a changed {what} must not pass the grader"
            );
        }
    }

    #[test]
    fn corrupted_minidumps_give_a_report_or_a_typed_error() {
        corrupt_and_inspect(&dump("exception.dmp"), 0x51_7CC1_B727_220A, 300);
    }
}
