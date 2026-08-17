#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::cast_possible_truncation
)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_native::error::Error;
use disrobe_pass_native::reconstruct_pdb_cxx;
use disrobe_pass_native::stub_emu::cpu::NoopHost;
use disrobe_pass_native::stub_emu::mem::MAX_MAP_BYTES;
use disrobe_pass_native::stub_emu::{Cpu, CpuMode, ExitReason, Memory, Perm, Reg};

#[path = "support/hostile_inputs.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod hostile_inputs;

#[path = "support/native_entry_points.rs"]
#[allow(clippy::redundant_pub_crate)]
mod native_entry_points;

use hostile_inputs::{
    COMPILED_VM_PROBE, HostileInput, SAMPLING_RULE, committed_image, compiled_vm_probe,
    crafted_elf, crafted_flat_image, crafted_macho_fat, crafted_macho_thin, crafted_pe32,
    crafted_pe32_plus, structural_variants_of, variants_of,
};
use native_entry_points::{Ctx, ENTRY_POINTS, Entry, PRECONDITION_GATED, Verdict};

struct PeakTrackingAlloc;

thread_local! {
    static PEAK_SINGLE_ALLOC: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation(size: usize) {
    let _ = PEAK_SINGLE_ALLOC.try_with(|peak: &Cell<usize>| {
        if size > peak.get() {
            peak.set(size);
        }
    });
}

fn reset_peak_allocation() {
    let _ = PEAK_SINGLE_ALLOC.try_with(|peak: &Cell<usize>| peak.set(0));
}

fn peak_allocation() -> usize {
    PEAK_SINGLE_ALLOC.try_with(Cell::get).unwrap_or_default()
}

unsafe impl GlobalAlloc for PeakTrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: PeakTrackingAlloc = PeakTrackingAlloc;

const CASE_WALL_CLOCK_BUDGET: Duration = Duration::from_mins(1);
const DEEP_ANALYSIS_INPUT_CAP: usize = 8192;
const CASE_ALLOC_CEILING: usize = 96 * 1024 * 1024;
const WATCHDOG_TICK: Duration = Duration::from_millis(200);
const SLOW_CASE_REPORT: Duration = Duration::from_millis(250);

static IN_FLIGHT: Mutex<Option<(String, Instant)>> = Mutex::new(None);

const EMPTY_INPUT_SUCCEEDS: &[(&str, &str)] = &[
    (
        "debug_info::parse_stabs",
        "an empty stabs table parses to an empty entry list, which claims no recovery",
    ),
    (
        "packers::kkrunchy_unpack::dis_filter",
        "filtering an empty code stream yields an empty stream and claims no recovery",
    ),
    (
        "packers::overlay::route_overlay_archive",
        "reports that there is no overlay to route, which is a negative answer rather than a claim",
    ),
];

fn start_watchdog() {
    thread::spawn(|| {
        loop {
            thread::sleep(WATCHDOG_TICK);
            let overdue: Option<String> = IN_FLIGHT.lock().ok().and_then(
                |guard: std::sync::MutexGuard<'_, Option<(String, Instant)>>| {
                    guard.as_ref().and_then(|(label, started)| {
                        (started.elapsed() > CASE_WALL_CLOCK_BUDGET).then(|| label.clone())
                    })
                },
            );
            if let Some(label) = overdue {
                eprintln!(
                    "resilience case {label} did not return within {CASE_WALL_CLOCK_BUDGET:?}. A \
                     parser or emulator that never returns on hostile input is a defect, and the \
                     suite fails here rather than hanging the machine."
                );
                std::process::exit(1);
            }
        }
    });
}

fn enter(label: &str) {
    if let Ok(mut guard) = IN_FLIGHT.lock() {
        *guard = Some((label.to_owned(), Instant::now()));
    }
}

fn leave() {
    if let Ok(mut guard) = IN_FLIGHT.lock() {
        *guard = None;
    }
}

struct BaseImage {
    name: &'static str,
    bytes: Vec<u8>,
}

fn base_images() -> Vec<BaseImage> {
    let mut bases: Vec<BaseImage> = vec![
        BaseImage {
            name: "crafted-pe32",
            bytes: crafted_pe32(),
        },
        BaseImage {
            name: "crafted-pe32plus",
            bytes: crafted_pe32_plus(),
        },
        BaseImage {
            name: "crafted-elf64le",
            bytes: crafted_elf(true, true),
        },
        BaseImage {
            name: "crafted-elf32be",
            bytes: crafted_elf(false, false),
        },
        BaseImage {
            name: "crafted-macho-thin",
            bytes: crafted_macho_thin(),
        },
        BaseImage {
            name: "crafted-macho-fat",
            bytes: crafted_macho_fat(),
        },
        BaseImage {
            name: "crafted-flat",
            bytes: crafted_flat_image(),
        },
    ];
    for (name, relative) in COMMITTED_BASES {
        if let Some(bytes) = committed_image(relative) {
            bases.push(BaseImage { name, bytes });
        }
    }
    bases
}

const COMMITTED_BASES: &[(&str, &str)] = &[
    ("formats-elf64", "formats/hello.elf64"),
    ("formats-macho64", "formats/hello.macho64.o"),
    ("formats-coff", "formats/hello.coff.x64.o"),
    ("formats-efi", "formats/hello.efi"),
    ("formats-pe64", "formats/hello.pe64.exe"),
    ("packed-fsg", "packers/fsg/Hash.packed.fsg.exe"),
    ("packed-mew", "packers/mew/Hash.packed.mew.exe"),
];

fn core_inputs(bases: &[BaseImage]) -> Vec<HostileInput> {
    let mut out: Vec<HostileInput> = vec![
        HostileInput {
            label: "empty".to_owned(),
            bytes: Vec::new(),
        },
        HostileInput {
            label: "one-byte".to_owned(),
            bytes: vec![0x4D],
        },
        HostileInput {
            label: "all-ones".to_owned(),
            bytes: vec![0xFFu8; 512],
        },
        HostileInput {
            label: "all-zero".to_owned(),
            bytes: vec![0u8; 512],
        },
    ];
    for base in bases {
        let variants: Vec<HostileInput> = variants_of(base.name, &base.bytes);
        let stride: usize = (variants.len() / 6).max(1);
        for (index, variant) in variants.into_iter().enumerate() {
            if index % stride == 0 {
                out.push(variant);
            }
        }
        out.extend(structural_variants_of(base.name, &base.bytes));
    }
    out
}

fn deep_inputs(bases: &[BaseImage]) -> Vec<HostileInput> {
    let mut out: Vec<HostileInput> = Vec::new();
    for base in bases {
        out.extend(variants_of(base.name, &base.bytes));
        out.extend(structural_variants_of(base.name, &base.bytes));
    }
    out
}

const REQUIRED_STRUCTURAL_SHAPES: &[&str] = &[
    "blank-sections",
    "zero-length-sections",
    "overlapping-sections",
    "unaligned-sections",
    "inflated-section-sizes",
    "inflated-section-count",
    "raw-pointer-past-eof",
    "headers-past-eof",
    "pe-offset-points-at-itself",
    "descending-section-order",
    "elf-phnum-max",
    "elf-shnum-max",
    "elf-phentsize-zero",
    "elf-program-headers-overlap-the-elf-header",
    "elf-segments-overlap",
    "elf-segments-zero-length",
    "macho-ncmds-max",
    "macho-first-cmdsize-zero",
    "macho-first-cmdsize-max",
    "macho-fat-nfat-max",
    "macho-fat-slice-offset-zero",
    "macho-fat-slice-offset-max",
];

fn report_slowest(findings: &Findings) {
    let mut slowest: Vec<(Duration, String)> = findings.slowest.clone();
    slowest.sort_by_key(|entry: &(Duration, String)| core::cmp::Reverse(entry.0));
    for (elapsed, label) in slowest.iter().take(20) {
        println!("slow case {elapsed:?} {label}");
    }
}

fn scratch() -> ScratchDir {
    ScratchDir::create("disrobe-native-resilience").expect("create scratch directory")
}

struct Findings {
    untyped_errors: Vec<String>,
    silent_success_on_empty: Vec<String>,
    reached: Vec<usize>,
    slowest: Vec<(Duration, String)>,
}

fn drive(inputs: &[HostileInput], scratch_dir: &Path, only_cheap: bool) -> Findings {
    let mut findings: Findings = Findings {
        untyped_errors: Vec::new(),
        silent_success_on_empty: Vec::new(),
        reached: vec![0; ENTRY_POINTS.len()],
        slowest: Vec::new(),
    };
    let companion: Vec<u8> = crafted_pe32_plus();
    for input in inputs {
        for (index, entry) in ENTRY_POINTS.iter().enumerate() {
            if only_cheap && !entry.cheap {
                continue;
            }
            if !entry.cheap && input.bytes.len() > DEEP_ANALYSIS_INPUT_CAP {
                continue;
            }
            let label: String = format!("{} on {}", entry.path, input.label);
            let ctx: Ctx<'_> = Ctx {
                bytes: &input.bytes,
                other: &companion,
                scratch: scratch_dir,
                label: &label,
            };
            reset_peak_allocation();
            enter(&label);
            let started: Instant = Instant::now();
            let verdict: Verdict = (entry.drive)(&ctx);
            leave();
            let elapsed: Duration = started.elapsed();
            if elapsed > SLOW_CASE_REPORT {
                findings.slowest.push((elapsed, label.clone()));
            }
            let peak: usize = peak_allocation();
            assert!(
                peak < CASE_ALLOC_CEILING,
                "{label} forced a {peak}-byte single allocation; a size field inside hostile input \
                 must never size an allocation directly"
            );
            match verdict {
                Verdict::Reached | Verdict::NotFallible => findings.reached[index] += 1,
                Verdict::Ok => {
                    findings.reached[index] += 1;
                    if input.label == "empty" {
                        findings.silent_success_on_empty.push(entry.path.to_owned());
                    }
                }
                Verdict::Failed(message) => {
                    findings.reached[index] += 1;
                    if !message.starts_with("DR-NATIVE-") {
                        findings.untyped_errors.push(format!("{label}: {message}"));
                    }
                }
                Verdict::Unreached => {}
            }
        }
    }
    findings
}

#[test]
fn the_driven_roster_covers_every_public_image_entry_point() {
    let derived: Vec<String> = derive_roster();
    assert!(
        derived.len() > 100,
        "the roster derivation found only {} entry points, so it stopped reading the source \
         correctly and would pass while covering nothing",
        derived.len()
    );
    let driven: Vec<&str> = ENTRY_POINTS.iter().map(|e: &Entry| e.path).collect();
    let missing: Vec<&String> = derived
        .iter()
        .filter(|path: &&String| !driven.contains(&path.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "these public entry points take a byte image and are not driven by the resilience suite; \
         add a row for each: {missing:#?}"
    );
    let stale: Vec<&&str> = driven
        .iter()
        .filter(|path: &&&str| !derived.iter().any(|d: &String| d == *path))
        .collect();
    assert!(
        stale.is_empty(),
        "these driven rows no longer name a public entry point: {stale:#?}"
    );
    println!(
        "{} public entry points take a byte image; all are driven",
        derived.len()
    );
}

fn derive_roster() -> Vec<String> {
    let src: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out: Vec<String> = Vec::new();
    collect_roster(&src, &src, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_roster(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path: PathBuf = entry.path();
        if path.is_dir() {
            collect_roster(root, &path, out);
            continue;
        }
        if path
            .extension()
            .is_none_or(|ext: &std::ffi::OsStr| ext != "rs")
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let mut module: String = relative
            .with_extension("")
            .components()
            .map(|part: std::path::Component<'_>| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<String>>()
            .join("::");
        if let Some(prefix) = module.strip_suffix("::mod") {
            module = prefix.to_owned();
        }
        if module == "lib" {
            module = String::new();
        }
        for name in image_entry_points(&text) {
            out.push(if module.is_empty() {
                name
            } else {
                format!("{module}::{name}")
            });
        }
    }
}

fn image_entry_points(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for start in text
        .match_indices("\npub fn ")
        .map(|(at, _): (usize, &str)| at + 1)
    {
        let rest: &str = &text[start..];
        let Some(open) = rest.find('(') else {
            continue;
        };
        let name: &str = rest["pub fn ".len()..open].trim();
        if !name
            .chars()
            .all(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        {
            continue;
        }
        let mut depth: usize = 0;
        let mut close: Option<usize> = None;
        for (index, ch) in rest[open..].char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + index);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else {
            continue;
        };
        let args: String = rest[open + 1..close]
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        let first: &str = args.split(',').next().unwrap_or_default().trim();
        let Some((_, kind)) = first.split_once(':') else {
            continue;
        };
        if kind.trim() == "&[u8]" {
            out.push(name.to_owned());
        }
    }
    out
}

#[test]
fn every_entry_point_survives_the_hostile_core() {
    start_watchdog();
    let bases: Vec<BaseImage> = base_images();
    assert!(
        bases.len() >= 8,
        "the base image set collapsed to {} images, so the sweep would cover almost nothing",
        bases.len()
    );
    let inputs: Vec<HostileInput> = core_inputs(&bases);
    let missing_shapes: Vec<&&str> = REQUIRED_STRUCTURAL_SHAPES
        .iter()
        .filter(|shape: &&&str| {
            !inputs
                .iter()
                .any(|input: &HostileInput| input.label.ends_with(**shape))
        })
        .collect();
    assert!(
        missing_shapes.is_empty(),
        "the structural rewriter produced no input for these declared section-table shapes, so the \
         suite would sweep past them: {missing_shapes:#?}"
    );
    let scratch_dir: ScratchDir = scratch();
    let findings: Findings = drive(&inputs, scratch_dir.path(), false);

    let never_reached: Vec<&str> = ENTRY_POINTS
        .iter()
        .zip(&findings.reached)
        .filter(|(entry, count): &(&Entry, &usize)| {
            **count == 0
                && !PRECONDITION_GATED
                    .iter()
                    .any(|(path, _): &(&str, &str)| *path == entry.path)
        })
        .map(|(entry, _): (&Entry, &usize)| entry.path)
        .collect();
    assert!(
        never_reached.is_empty(),
        "these rows never ran their entry point on any hostile input, so they grade nothing: {never_reached:#?}"
    );
    assert!(
        findings.untyped_errors.is_empty(),
        "these failures did not carry a DR-NATIVE error code, so the caller cannot tell what went \
         wrong: {:#?}",
        findings.untyped_errors
    );
    let mut succeeded_on_empty: Vec<String> = findings.silent_success_on_empty.clone();
    succeeded_on_empty.sort();
    succeeded_on_empty.dedup();
    let declared: Vec<&str> = EMPTY_INPUT_SUCCEEDS
        .iter()
        .map(|(path, _): &(&str, &str)| *path)
        .collect();
    let undeclared: Vec<&String> = succeeded_on_empty
        .iter()
        .filter(|path: &&String| !declared.contains(&path.as_str()))
        .collect();
    assert!(
        undeclared.is_empty(),
        "these fallible entry points reported success on an empty image and no reason is recorded \
         for it, which is how a silent success on garbage ships: {undeclared:#?}"
    );
    let stale: Vec<&(&str, &str)> = EMPTY_INPUT_SUCCEEDS
        .iter()
        .filter(|(path, _): &&(&str, &str)| {
            !succeeded_on_empty.iter().any(|seen: &String| seen == path)
        })
        .collect();
    assert!(
        stale.is_empty(),
        "these entry points no longer report success on an empty image, so their recorded reason is \
         out of date: {stale:#?}"
    );
    report_slowest(&findings);
    println!(
        "drove {} entry points over {} hostile inputs; sampling rule: {SAMPLING_RULE}",
        ENTRY_POINTS.len(),
        inputs.len()
    );
}

#[test]
fn the_parse_surfaces_survive_the_deep_mutation_matrix() {
    start_watchdog();
    let bases: Vec<BaseImage> = base_images();
    let inputs: Vec<HostileInput> = deep_inputs(&bases);
    assert!(
        inputs.len() > 400,
        "the deep matrix produced only {} inputs, so the mutation engine is not generating variants",
        inputs.len()
    );
    let scratch_dir: ScratchDir = scratch();
    let findings: Findings = drive(&inputs, scratch_dir.path(), true);
    assert!(
        findings.untyped_errors.is_empty(),
        "these failures did not carry a DR-NATIVE error code: {:#?}",
        findings.untyped_errors
    );
    let cheap: usize = ENTRY_POINTS
        .iter()
        .filter(|entry: &&Entry| entry.cheap)
        .count();
    println!(
        "drove {cheap} parse surfaces over {} mutated inputs",
        inputs.len()
    );
}

#[test]
fn a_precondition_gated_entry_point_is_reached_on_the_fixture_that_satisfies_it() {
    start_watchdog();
    let scratch_dir: ScratchDir = scratch();
    let companion: Vec<u8> = crafted_pe32_plus();
    for (path, fixture) in PRECONDITION_GATED {
        let source: Option<Vec<u8>> = if *fixture == COMPILED_VM_PROBE {
            compiled_vm_probe()
        } else {
            committed_image(fixture)
        };
        let Some(base): Option<Vec<u8>> = source else {
            panic!(
                "{path} is reachable only through {fixture}, and that input could not be produced, \
                 so the entry point would never be driven at all"
            );
        };
        let entry: &Entry = ENTRY_POINTS
            .iter()
            .find(|entry: &&Entry| entry.path == *path)
            .expect("a gated path must name a driven entry point");
        let mut reached: usize = 0;
        for input in variants_of(fixture, &base) {
            let label: String = format!("{path} on {}", input.label);
            let ctx: Ctx<'_> = Ctx {
                bytes: &input.bytes,
                other: &companion,
                scratch: scratch_dir.path(),
                label: &label,
            };
            reset_peak_allocation();
            enter(&label);
            let verdict: Verdict = (entry.drive)(&ctx);
            leave();
            let peak: usize = peak_allocation();
            assert!(
                peak < CASE_ALLOC_CEILING,
                "{label} forced a {peak}-byte single allocation"
            );
            match verdict {
                Verdict::Unreached => {}
                Verdict::Failed(message) => {
                    reached += 1;
                    assert!(
                        message.starts_with("DR-NATIVE-"),
                        "{label} failed without a DR-NATIVE error code: {message}"
                    );
                }
                Verdict::Ok | Verdict::NotFallible | Verdict::Reached => reached += 1,
            }
        }
        assert!(
            reached > 0,
            "{path} was never reached even on {fixture}, the fixture chosen to satisfy its \
             precondition, so nothing drives it"
        );
        println!("{path} reached {reached} times on {fixture}");
    }
}

const STUB_STEP_CAP: u64 = 200_000;
const STUB_CODE_BASE: u64 = 0x0040_0000;
const STUB_STACK_BASE: u64 = 0x0080_0000;
const STUB_PAGE_BYTES: u64 = 0x1000;

const EXIT_STEP_CAP: &str = "StepCap";
const EXIT_REP_LIMIT: &str = "RepLimit";
const EXIT_JUMPED_OUT_OF_RANGE: &str = "JumpedOutOfRange";
const EXIT_GUEST_FAULT: &str = "GuestFault";
const EXIT_UNSUPPORTED_INSTR: &str = "UnsupportedInstr";

struct HostileStub {
    label: &'static str,
    code: &'static [u8],
    bounded_by: &'static [&'static str],
}

const HOSTILE_STUBS: &[HostileStub] = &[
    HostileStub {
        label: "never-terminates",
        code: &[0xEB, 0xFE],
        bounded_by: &[EXIT_STEP_CAP],
    },
    HostileStub {
        label: "reads-outside-its-mapping",
        code: &[0xA1, 0xEF, 0xBE, 0xAD, 0xDE],
        bounded_by: &[EXIT_GUEST_FAULT],
    },
    HostileStub {
        label: "writes-to-an-unmapped-page",
        code: &[0xA3, 0xEF, 0xBE, 0xAD, 0xDE],
        bounded_by: &[EXIT_GUEST_FAULT],
    },
    HostileStub {
        label: "writes-to-a-read-only-page",
        code: &[0xA3, 0x00, 0x00, 0x90, 0x00],
        bounded_by: &[EXIT_GUEST_FAULT],
    },
    HostileStub {
        label: "executes-into-unmapped-memory",
        code: &[0xE9, 0x00, 0x00, 0x00, 0x40],
        bounded_by: &[EXIT_JUMPED_OUT_OF_RANGE, EXIT_GUEST_FAULT],
    },
    HostileStub {
        label: "returns-through-an-uninitialised-stack",
        code: &[0xC3],
        bounded_by: &[EXIT_JUMPED_OUT_OF_RANGE, EXIT_GUEST_FAULT],
    },
    HostileStub {
        label: "divides-by-zero",
        code: &[0x31, 0xC0, 0x31, 0xD2, 0xF7, 0xF0],
        bounded_by: &[EXIT_GUEST_FAULT],
    },
    HostileStub {
        label: "repeats-a-string-move-across-the-address-space",
        code: &[0xB9, 0xFF, 0xFF, 0xFF, 0xFF, 0xF3, 0xA4],
        bounded_by: &[EXIT_REP_LIMIT, EXIT_GUEST_FAULT],
    },
    HostileStub {
        label: "runs-off-the-end-of-its-page-into-junk",
        code: &[0xFF, 0xFF, 0xFF, 0xFF],
        bounded_by: &[EXIT_UNSUPPORTED_INSTR, EXIT_GUEST_FAULT],
    },
];

const fn exit_kind(exit: &ExitReason) -> &'static str {
    match *exit {
        ExitReason::StepCap(_) => EXIT_STEP_CAP,
        ExitReason::RepLimit(_) => EXIT_REP_LIMIT,
        ExitReason::JumpedOutOfRange { .. } => EXIT_JUMPED_OUT_OF_RANGE,
        ExitReason::HostHalt(_) => "HostHalt",
        ExitReason::UnsupportedInstr { .. } => EXIT_UNSUPPORTED_INSTR,
        ExitReason::GuestFault(_) => EXIT_GUEST_FAULT,
    }
}

fn run_hostile_stub(code: &[u8]) -> core::result::Result<ExitReason, String> {
    let mut cpu: Cpu = Cpu::new(CpuMode::Bits32);
    cpu.mem
        .map(STUB_CODE_BASE, STUB_PAGE_BYTES, Perm::RWX)
        .map_err(|error: Error| error.to_string())?;
    cpu.mem
        .map(STUB_STACK_BASE, STUB_PAGE_BYTES, Perm::RW)
        .map_err(|error: Error| error.to_string())?;
    cpu.mem
        .map(0x0090_0000, STUB_PAGE_BYTES, Perm::R)
        .map_err(|error: Error| error.to_string())?;
    cpu.mem
        .write(STUB_CODE_BASE, code)
        .map_err(|error: Error| error.to_string())?;
    cpu.regs.rip = STUB_CODE_BASE;
    cpu.regs
        .set(Reg::Rsp, STUB_STACK_BASE + STUB_PAGE_BYTES / 2);
    cpu.run(&mut NoopHost, STUB_STEP_CAP)
        .map_err(|error: Error| error.to_string())
}

#[test]
fn the_stub_emulator_bounds_a_hostile_stub_rather_than_hanging_or_faulting_the_host() {
    start_watchdog();
    for stub in HOSTILE_STUBS {
        let label: String = format!("stub_emu on a stub that {}", stub.label);
        reset_peak_allocation();
        enter(&label);
        let started: Instant = Instant::now();
        let outcome: core::result::Result<ExitReason, String> = run_hostile_stub(stub.code);
        leave();
        let elapsed: Duration = started.elapsed();
        let peak: usize = peak_allocation();
        assert!(
            peak < CASE_ALLOC_CEILING,
            "{label} forced a {peak}-byte single allocation"
        );
        assert!(
            elapsed < CASE_WALL_CLOCK_BUDGET,
            "{label} took {elapsed:?}, past the {CASE_WALL_CLOCK_BUDGET:?} budget"
        );
        let observed: String = match outcome {
            Ok(exit) => {
                let kind: &str = exit_kind(&exit);
                assert!(
                    stub.bounded_by.contains(&kind),
                    "{label} exited as {kind}, and the only bounded stops for this stub are {:?}",
                    stub.bounded_by
                );
                format!("{kind} ({exit:?})")
            }
            Err(message) => {
                assert!(
                    message.starts_with("DR-NATIVE-"),
                    "{label} failed without a DR-NATIVE error code: {message}"
                );
                message
            }
        };
        println!("{label} stopped as {observed} in {elapsed:?}, peak allocation {peak} bytes");
    }
}

#[test]
fn the_emulator_memory_refuses_a_hostile_size_rather_than_reserving_it() {
    let mut mem: Memory = Memory::new();
    reset_peak_allocation();
    assert!(mem.map(STUB_CODE_BASE, u64::MAX, Perm::RW).is_err());
    assert!(
        mem.map(STUB_CODE_BASE, MAX_MAP_BYTES + 1, Perm::RW)
            .is_err()
    );
    assert!(mem.map(u64::MAX - 0x10, STUB_PAGE_BYTES, Perm::RW).is_err());
    assert!(mem.map(STUB_CODE_BASE, 0, Perm::RW).is_ok());
    assert!(mem.read(STUB_CODE_BASE, usize::MAX).is_err());
    assert!(mem.read(STUB_CODE_BASE, 1).is_err());

    mem.map(STUB_CODE_BASE, STUB_PAGE_BYTES, Perm::R)
        .expect("a page-sized read-only map is legal");
    assert!(mem.read(STUB_CODE_BASE, 1).is_ok());
    assert!(mem.write(STUB_CODE_BASE, &[0u8]).is_err());
    assert!(mem.read(STUB_CODE_BASE, usize::MAX).is_err());
    assert!(mem.read(u64::MAX, 1).is_err());

    let peak: usize = peak_allocation();
    assert!(
        peak < CASE_ALLOC_CEILING,
        "a hostile map or read reserved {peak} bytes"
    );
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn first_embedded_argument_list(pdb_bytes: &[u8]) -> Option<Vec<u8>> {
    let cursor: Cursor<&[u8]> = Cursor::new(pdb_bytes);
    let mut pdb_file: pdb::PDB<'_, Cursor<&[u8]>> = pdb::PDB::open(cursor).ok()?;
    let stream = pdb_file.raw_stream(pdb::StreamIndex(2)).ok()??;
    let bytes: &[u8] = stream.as_slice();
    let header_size: usize = read_u32(bytes, 4)? as usize;
    let record_bytes: usize = read_u32(bytes, 16)? as usize;
    let end: usize = header_size.checked_add(record_bytes)?;
    let mut offset: usize = header_size;
    while offset < end {
        let length: usize = usize::from(read_u16(bytes, offset)?);
        let start: usize = offset.checked_add(2)?;
        let next: usize = start.checked_add(length)?;
        let record: &[u8] = bytes.get(start..next)?;
        if read_u16(record, 0) == Some(0x1201)
            && record.len() == 10
            && pdb_bytes
                .windows(record.len())
                .any(|candidate: &[u8]| candidate == record)
        {
            return Some(record.to_vec());
        }
        offset = next;
    }
    None
}

fn pdb_with_argument_count(count: u32) -> Vec<u8> {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("pdb_cxx_recovery.pdb");
    let mut bytes: Vec<u8> =
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let record: Vec<u8> = first_embedded_argument_list(&bytes)
        .expect("fixture must contain an embedded LF_ARGLIST record");
    let starts: Vec<usize> = bytes
        .windows(record.len())
        .enumerate()
        .filter_map(|(offset, candidate): (usize, &[u8])| (candidate == record).then_some(offset))
        .collect();
    assert!(
        !starts.is_empty(),
        "selected LF_ARGLIST must be embedded in fixture bytes"
    );
    for start in starts {
        bytes[start + 2..start + 6].copy_from_slice(&count.to_le_bytes());
    }
    bytes
}

#[test]
fn pdb_argument_list_count_is_bounded_before_dependency_allocation() {
    let bytes: Vec<u8> = pdb_with_argument_count(u32::MAX);
    reset_peak_allocation();
    let result = reconstruct_pdb_cxx(&bytes);
    let peak: usize = peak_allocation();
    let message: String = result
        .expect_err("oversized LF_ARGLIST count must refuse")
        .to_string();
    assert!(message.contains("LF_ARGLIST"), "{message}");
    assert!(message.contains("4294967295"), "{message}");
    assert!(message.contains("record holds at most"), "{message}");
    assert!(
        peak < CASE_ALLOC_CEILING,
        "a ten-byte LF_ARGLIST record forced a {peak}-byte allocation"
    );
}
