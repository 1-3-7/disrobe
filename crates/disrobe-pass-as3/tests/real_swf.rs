#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,
    clippy::missing_const_for_fn
)]

mod common;

use std::path::PathBuf;

use disrobe_pass_as3::abc::{DisasmLine, MethodInfo, disasm};
use disrobe_pass_as3::lifter::{LiftedBody, Stmt, lift_body};
use disrobe_pass_as3::swf::{Swf, SwfCompression, TagCode};
use disrobe_pass_as3::{AbcFile, DoAbc, abc, decompile, swf};

#[derive(Debug, Default, Clone, Copy)]
struct StructureTotals {
    bodies: usize,
    structurally_recovered: usize,
    for_loops: usize,
    for_each_loops: usize,
    for_in_loops: usize,
    while_loops: usize,
    do_while_loops: usize,
    if_blocks: usize,
    try_blocks: usize,
    residual_goto_in_recovered: usize,
    bodies_with_dropped_opcodes: usize,
}

fn count_structures(stmts: &[Stmt], totals: &mut StructureTotals) {
    for stmt in stmts {
        match stmt {
            Stmt::For { body, .. } => {
                totals.for_loops += 1;
                count_structures(body, totals);
            }
            Stmt::ForEach { body, .. } => {
                totals.for_each_loops += 1;
                count_structures(body, totals);
            }
            Stmt::ForIn { body, .. } => {
                totals.for_in_loops += 1;
                count_structures(body, totals);
            }
            Stmt::While { body, .. } => {
                totals.while_loops += 1;
                count_structures(body, totals);
            }
            Stmt::DoWhile { body, .. } => {
                totals.do_while_loops += 1;
                count_structures(body, totals);
            }
            Stmt::IfBlock { body, .. } => {
                totals.if_blocks += 1;
                count_structures(body, totals);
            }
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                totals.if_blocks += 1;
                count_structures(then_body, totals);
                count_structures(else_body, totals);
            }
            Stmt::Try { body, catches } => {
                totals.try_blocks += 1;
                count_structures(body, totals);
                for catch in catches {
                    count_structures(&catch.body, totals);
                }
            }
            Stmt::With { body, .. } => count_structures(body, totals),
            Stmt::StructuredSwitch { cases, .. } => {
                for case in cases {
                    count_structures(&case.body, totals);
                }
            }
            _ => {}
        }
    }
}

fn has_residual_goto(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s: &Stmt| match s {
        Stmt::Jump { .. } | Stmt::If { .. } | Stmt::Label(_) | Stmt::Switch { .. } => true,
        Stmt::For { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::ForIn { body, .. }
        | Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::IfBlock { body, .. }
        | Stmt::With { body, .. } => has_residual_goto(body),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => has_residual_goto(then_body) || has_residual_goto(else_body),
        Stmt::Try { body, catches } => {
            has_residual_goto(body) || catches.iter().any(|c| has_residual_goto(&c.body))
        }
        Stmt::StructuredSwitch { cases, .. } => cases.iter().any(|c| has_residual_goto(&c.body)),
        _ => false,
    })
}

fn structure_corpus() -> Option<StructureTotals> {
    if !common::require_corpus("corpus control-flow restructuring", &corpus_root()) {
        return None;
    }
    let dir: PathBuf = corpus_root();
    let entries: std::fs::ReadDir = std::fs::read_dir(&dir).ok()?;
    let mut totals: StructureTotals = StructureTotals::default();
    let mut seen: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("swf") {
            continue;
        }
        seen += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            for body in &abc.method_bodies {
                let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
                let Ok(lifted): Result<LiftedBody, _> = lift_body(&abc, body, info) else {
                    continue;
                };
                totals.bodies += 1;
                if !lifted.dropped_opcodes.is_empty() {
                    totals.bodies_with_dropped_opcodes += 1;
                }
                if lifted.structurally_recovered {
                    totals.structurally_recovered += 1;
                    if has_residual_goto(&lifted.statements) {
                        totals.residual_goto_in_recovered += 1;
                    }
                }
                count_structures(&lifted.statements, &mut totals);
            }
        }
    }
    assert!(
        seen > 0,
        "the corpus directory is present but no SWF in it parsed, so this case would grade a \
         smaller population than it claims"
    );
    Some(totals)
}

#[test]
fn corpus_control_flow_restructuring_is_sound_and_productive() {
    let Some(totals): Option<StructureTotals> = structure_corpus() else {
        return;
    };
    eprintln!("AS3 corpus restructuring totals: {totals:?}");
    assert!(totals.bodies > 1000, "corpus must lift many bodies");
    assert!(
        totals.while_loops + totals.for_loops + totals.for_each_loops + totals.for_in_loops > 0,
        "real compiler-emitted ABC must yield recovered loops"
    );
    assert!(
        totals.if_blocks > 0,
        "real ABC must yield recovered if/else blocks"
    );
    assert_eq!(
        totals.residual_goto_in_recovered, 0,
        "a structurally recovered body must never carry residual goto/label/raw-if scaffolding"
    );
    assert_eq!(
        totals.bodies_with_dropped_opcodes, 0,
        "every opcode in real compiler-emitted ABC must be modelled (newcatch, dxnslate, scope ops included)"
    );
    assert!(
        totals.for_loops + totals.for_each_loops + totals.for_in_loops > 0,
        "the for/for-each/for-in restructurer must fire on real compiler output"
    );
}

use disrobe_pass_as3::lifter::{LocalNames, local_names_for, render_body};

fn rendered_corpus_bodies() -> Option<(usize, usize, String)> {
    if !common::require_corpus("corpus rendered bodies", &corpus_root()) {
        return None;
    }
    let dir: PathBuf = corpus_root();
    let entries: std::fs::ReadDir = std::fs::read_dir(&dir).ok()?;
    let mut bodies: usize = 0;
    let mut structurally_recovered: usize = 0;
    let mut sample_leak: String = String::new();
    let mut seen: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("swf") {
            continue;
        }
        seen += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            for body in &abc.method_bodies {
                let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
                let Ok(lifted): Result<LiftedBody, _> = lift_body(&abc, body, info) else {
                    continue;
                };
                bodies += 1;
                if lifted.structurally_recovered {
                    structurally_recovered += 1;
                }
                let names: LocalNames = local_names_for(&abc, info);
                let text: String = render_body(&lifted, &names, "");
                if sample_leak.is_empty()
                    && (text.contains("http://adobe.com/AS3/2006/builtin.")
                        || text.contains("http://www.adobe.com/2006/actionscript"))
                {
                    sample_leak = text;
                }
            }
        }
    }
    assert!(
        seen > 0,
        "the corpus directory is present but no SWF in it parsed, so this case would grade a \
         smaller population than it claims"
    );
    Some((bodies, structurally_recovered, sample_leak))
}

#[test]
fn property_access_never_leaks_a_namespace_uri() {
    let Some((bodies, _full, leak)): Option<(usize, usize, String)> = rendered_corpus_bodies()
    else {
        return;
    };
    assert!(bodies > 1000, "corpus must lift many bodies");
    assert!(
        leak.is_empty(),
        "a property/method access must render its simple name, never the resolution namespace URI; leaked body:\n{leak}"
    );
}

#[derive(Debug, Default, Clone, Copy)]
struct DispatchTotals {
    disassembled: usize,
    lifted: usize,
    folded: usize,
}

fn count_raw_switches(stmts: &[Stmt]) -> usize {
    stmts
        .iter()
        .map(|stmt: &Stmt| match stmt {
            Stmt::Switch { .. } => 1,
            Stmt::For { body, .. }
            | Stmt::ForEach { body, .. }
            | Stmt::ForIn { body, .. }
            | Stmt::While { body, .. }
            | Stmt::DoWhile { body, .. }
            | Stmt::IfBlock { body, .. }
            | Stmt::With { body, .. } => count_raw_switches(body),
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => count_raw_switches(then_body) + count_raw_switches(else_body),
            Stmt::Try { body, catches } => {
                count_raw_switches(body)
                    + catches
                        .iter()
                        .map(|catch| count_raw_switches(&catch.body))
                        .sum::<usize>()
            }
            Stmt::StructuredSwitch { cases, .. } => cases
                .iter()
                .map(|case| count_raw_switches(&case.body))
                .sum(),
            _ => 0,
        })
        .sum()
}

fn dispatch_totals() -> Option<DispatchTotals> {
    if !common::require_corpus("corpus lookupswitch dispatch", &corpus_root()) {
        return None;
    }
    let dir: PathBuf = corpus_root();
    let entries: std::fs::ReadDir = std::fs::read_dir(&dir).ok()?;
    let mut totals: DispatchTotals = DispatchTotals::default();
    let mut seen: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("swf") {
            continue;
        }
        seen += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            for body in &abc.method_bodies {
                if let Ok(lines) = disasm(&body.code) {
                    totals.disassembled += lines
                        .iter()
                        .filter(|line: &&DisasmLine| line.mnemonic == "lookupswitch")
                        .count();
                }
                let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
                let Ok(raw): Result<Vec<Stmt>, _> =
                    disrobe_pass_as3::lifter::lift_body_raw(&abc, body, info)
                else {
                    continue;
                };
                let Ok(lifted): Result<LiftedBody, _> = lift_body(&abc, body, info) else {
                    continue;
                };
                let before: usize = count_raw_switches(&raw);
                let after: usize = count_raw_switches(&lifted.statements);
                totals.lifted += before;
                totals.folded += before.saturating_sub(after);
            }
        }
    }
    (seen > 0).then_some(totals)
}

#[test]
fn corpus_lookupswitch_dispatch_recovery_holds_its_measured_floor() {
    let Some(totals): Option<DispatchTotals> = dispatch_totals() else {
        return;
    };
    let pct: f64 = 100.0 * totals.folded as f64 / totals.lifted as f64;
    eprintln!(
        "AS3 corpus lookupswitch folds: {}/{} = {pct:.2}% (disassembled {})",
        totals.folded, totals.lifted, totals.disassembled
    );
    assert!(
        totals.lifted >= 150,
        "the dispatch population must stay large enough to measure; got {} lifted from {} \
         disassembled lookupswitch instructions",
        totals.lifted,
        totals.disassembled
    );
    assert!(
        totals.disassembled >= totals.lifted,
        "every lifted dispatch must come from a lookupswitch the disassembler also found; got \
         {} lifted against {} disassembled",
        totals.lifted,
        totals.disassembled
    );
    assert!(
        totals.folded * 1000 >= totals.lifted * 198,
        "real compiler-emitted lookupswitch dispatch must keep folding into structured \
         switches at its measured floor (>=19.8%); got {}/{} = {pct:.2}%. This floor sat at \
         19.2 percent for a while because one dispatch lay in a region a scope refusal had \
         poisoned. Proving that a loop whose body never touches the scope stack reconciles \
         at its head removed that refusal and the fold returned, so the number came back by \
         fixing the cause rather than by relaxing a check. \
         This is a ratchet over a fixed corpus of real Flash titles that is not \
         redistributable and is absent from every fresh checkout, so the number is \
         reproducible only against that exact population and is not a published figure",
        totals.folded,
        totals.lifted
    );
}

#[test]
fn corpus_recovery_rate_holds_an_honest_floor() {
    let Some((bodies, full, _leak)): Option<(usize, usize, String)> = rendered_corpus_bodies()
    else {
        return;
    };
    let pct: f64 = 100.0 * full as f64 / bodies as f64;
    eprintln!("AS3 corpus full-recovery: {full}/{bodies} = {pct:.2}%");
    assert!(
        bodies > 1000,
        "this case asserts a rate, so its denominator has to be floored too; a body that \
         fails to lift is skipped rather than counted, and without this a shrinking \
         population would keep reporting a healthy percentage over almost nothing: {bodies}"
    );
    assert!(
        full * 1000 >= bodies * 940,
        "fully-recovered share must hold the post-restructuring floor (>=94.0%); got \
         {full}/{bodies} = {pct:.2}%. This is a ratchet over a fixed corpus of real Flash titles that is not \
         redistributable and is absent from every fresh checkout, so the number is \
         reproducible only against that exact population and is not a published figure"
    );
}

fn body_render_has_phi(text: &str) -> bool {
    let bytes: &[u8] = text.as_bytes();
    let mut i: usize = 0;
    while i + 3 < bytes.len() {
        if &bytes[i..i + 3] == b"phi" {
            let before_ok: bool = i == 0 || !bytes[i - 1].is_ascii_alphanumeric();
            if before_ok && bytes[i + 3].is_ascii_digit() {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[test]
fn no_structurally_recovered_body_renders_a_phi_placeholder() {
    let dir: PathBuf = corpus_root();
    if !common::require_corpus("corpus phi placeholders", &dir) {
        return;
    }
    let Ok(entries): Result<std::fs::ReadDir, _> = std::fs::read_dir(&dir) else {
        return;
    };
    let mut bodies: usize = 0;
    let mut recovered: usize = 0;
    let mut inflated: usize = 0;
    let mut sample: String = String::new();
    let mut seen: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("swf") {
            continue;
        }
        seen += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let Ok(parsed): Result<Swf, _> = swf::parse(&bytes) else {
            continue;
        };
        for blob in parsed.collect_do_abc() {
            let Ok(abc): Result<AbcFile, _> = abc::parse(&blob.abc_bytes) else {
                continue;
            };
            for body in &abc.method_bodies {
                let info: Option<&MethodInfo> = abc.methods.get(body.method as usize);
                let Ok(lifted): Result<LiftedBody, _> = lift_body(&abc, body, info) else {
                    continue;
                };
                bodies += 1;
                if !lifted.structurally_recovered {
                    continue;
                }
                recovered += 1;
                let names: LocalNames = local_names_for(&abc, info);
                let text: String = render_body(&lifted, &names, "");
                if body_render_has_phi(&text) {
                    inflated += 1;
                    if sample.is_empty() {
                        sample = text;
                    }
                }
            }
        }
    }
    assert!(
        seen > 0,
        "the corpus directory is present but no SWF in it parsed, so this case would grade a \
         smaller population than it claims"
    );
    assert!(bodies > 1000, "corpus must lift many bodies");
    assert!(
        recovered > 1000,
        "corpus must structurally recover many bodies"
    );
    assert_eq!(
        inflated, 0,
        "a structurally recovered body must never render an unresolved phi stack-join placeholder (soundness: a surviving phi must count against structural recovery); leaked body:\n{sample}"
    );
}

fn corpus_root() -> PathBuf {
    if let Ok(over) = std::env::var("DR_AS3_CORPUS") {
        return PathBuf::from(over);
    }
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
}

fn load_fixture(name: &str) -> Option<Vec<u8>> {
    if !common::require_corpus_fixture("corpus fixture", &corpus_root(), name) {
        return None;
    }
    let path: PathBuf = corpus_root().join(name);
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(error) => panic!(
            "the corpus gate reported {} present, so failing to read it is a damaged corpus \
             rather than an absent one: {error}",
            path.display()
        ),
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct CorpusTotals {
    files_with_abc: usize,
    abc_blobs: usize,
    methods: usize,
    instances: usize,
    opcodes: usize,
    decompiled_classes: usize,
}

fn parse_corpus() -> Option<CorpusTotals> {
    if !common::require_corpus("corpus parse", &corpus_root()) {
        return None;
    }
    let dir: PathBuf = corpus_root();
    let entries: std::fs::ReadDir = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(error) => panic!(
            "the corpus gate reported {} readable, so failing to list it is a damaged corpus \
             rather than an absent one: {error}",
            dir.display()
        ),
    };
    let mut totals: CorpusTotals = CorpusTotals::default();
    let mut swf_seen: usize = 0;
    for entry in entries {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("swf") {
            continue;
        }
        swf_seen += 1;
        let bytes: Vec<u8> = std::fs::read(&path).expect("read swf");
        let parsed: Swf =
            swf::parse(&bytes).unwrap_or_else(|e| panic!("swf parse {}: {e}", path.display()));
        let blobs: Vec<DoAbc> = parsed.collect_do_abc();
        if blobs.is_empty() {
            continue;
        }
        totals.files_with_abc += 1;
        for blob in &blobs {
            assert!(
                !blob.abc_bytes.is_empty(),
                "DoABC payload empty in {}",
                path.display()
            );
            let abc: AbcFile = abc::parse(&blob.abc_bytes).unwrap_or_else(|e| {
                panic!(
                    "abc parse must succeed for {} blob '{}': {e}",
                    path.display(),
                    blob.name
                )
            });
            assert_eq!(abc.minor, abc::ABC_MINOR, "{}", path.display());
            assert_eq!(abc.major, abc::ABC_MAJOR, "{}", path.display());
            totals.abc_blobs += 1;
            totals.methods += abc.methods.len();
            totals.instances += abc.instances.len();
            for body in &abc.method_bodies {
                let lines: Vec<DisasmLine> = disasm(&body.code).unwrap_or_else(|e| {
                    panic!("disasm {} blob '{}': {e}", path.display(), blob.name)
                });
                totals.opcodes += lines.len();
            }
            for instance in &abc.instances {
                if let Ok(skel) = decompile::render_class_skeleton(&abc, instance) {
                    assert!(
                        skel.contains("class ") || skel.contains("interface "),
                        "skeleton must declare a class/interface in {}",
                        path.display()
                    );
                    totals.decompiled_classes += 1;
                }
            }
        }
    }
    assert!(
        swf_seen > 0,
        "the corpus directory {} is present but holds no parsable .swf, so this case would \
         grade a smaller population than it claims",
        dir.display()
    );
    Some(totals)
}

#[test]
fn detects_uncompressed_fws_signature() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("A-Blast_Liberation.swf") else {
        return;
    };
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::None);
}

#[test]
fn detects_zlib_cws_signature() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("4_Ball_Pong.swf") else {
        return;
    };
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::Zlib);
}

#[test]
fn detects_lzma_zws_signature() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("10_More_Bullets.swf") else {
        return;
    };
    let compression: SwfCompression = swf::detect(&bytes).expect("detect signature");
    assert_eq!(compression, SwfCompression::Lzma);
}

#[test]
fn parses_real_uncompressed_swf_header_and_tags() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("A-Blast_Liberation.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse FWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::None);
    assert!(parsed.header.version >= 1);
    assert!(parsed.header.frame_count >= 1);
    assert!(
        parsed.tags.len() >= 5,
        "expected non-trivial tag stream, got {}",
        parsed.tags.len()
    );
    assert!(
        parsed
            .tags
            .iter()
            .any(|t: &swf::SwfTag| t.code == TagCode::END)
    );
}

#[test]
fn parses_real_zlib_swf_header_and_tags() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("4_Ball_Pong.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse CWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::Zlib);
    assert!(parsed.header.version >= 6);
    assert!(parsed.tags.len() >= 5);
}

#[test]
fn parses_real_lzma_swf_extracts_and_parses_do_abc() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("10_More_Bullets.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse ZWS swf");
    assert_eq!(parsed.header.compression, SwfCompression::Lzma);
    let abc_blobs: Vec<DoAbc> = parsed.collect_do_abc();
    assert!(
        !abc_blobs.is_empty(),
        "AS3-era LZMA SWF should contain at least one DoABC tag"
    );
    let mut total_opcodes: usize = 0;
    for blob in &abc_blobs {
        assert!(!blob.abc_bytes.is_empty(), "DoABC payload empty");
        let abc: AbcFile = abc::parse(&blob.abc_bytes)
            .unwrap_or_else(|e| panic!("abc parse '{}': {e}", blob.name));
        assert_eq!(abc.minor, abc::ABC_MINOR);
        assert_eq!(abc.major, abc::ABC_MAJOR);
        assert!(
            !abc.cpool.strings.is_empty(),
            "real ABC must have a populated string pool"
        );
        for body in &abc.method_bodies {
            total_opcodes += disasm(&body.code)
                .unwrap_or_else(|e| panic!("disasm '{}': {e}", blob.name))
                .len();
        }
    }
    assert!(
        total_opcodes > 0,
        "real ABC must disassemble to a non-zero opcode stream"
    );
}

#[test]
fn parses_real_zlib_3d_motorbike_walks_tag_counts() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("3D_Motorbike_Racer.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse swf");
    let counts: std::collections::BTreeMap<TagCode, usize> = parsed.tag_counts();
    assert!(!counts.is_empty());
    let total: usize = counts.values().sum();
    assert!(
        total >= 20,
        "expected many tags in 3D_Motorbike_Racer.swf, got {total}"
    );
}

#[test]
fn parses_real_atv_megafile_abc_with_classes_and_opcodes() {
    let Some(bytes): Option<Vec<u8>> = load_fixture("ATV_Cross_Canada.swf") else {
        return;
    };
    let parsed: Swf = swf::parse(&bytes).expect("parse megafile swf");
    assert!(parsed.header.version >= 10, "ATV is AS3-era v11");
    let counts: std::collections::BTreeMap<TagCode, usize> = parsed.tag_counts();
    let total: usize = counts.values().sum();
    assert!(
        total >= 50,
        "expected megafile SWF to have many tags, got {total}"
    );
    let abc_blobs: Vec<DoAbc> = parsed.collect_do_abc();
    assert!(
        !abc_blobs.is_empty(),
        "ATV megafile must contain DoABC tags"
    );
    let mut total_classes: usize = 0;
    let mut total_opcodes: usize = 0;
    let mut total_decompiled: usize = 0;
    for blob in &abc_blobs {
        let abc: AbcFile = abc::parse(&blob.abc_bytes)
            .unwrap_or_else(|e| panic!("abc parse '{}': {e}", blob.name));
        assert_eq!(abc.minor, abc::ABC_MINOR);
        assert_eq!(abc.major, abc::ABC_MAJOR);
        total_classes += abc.instances.len();
        for body in &abc.method_bodies {
            total_opcodes += disasm(&body.code)
                .unwrap_or_else(|e| panic!("disasm '{}': {e}", blob.name))
                .len();
        }
        for instance in &abc.instances {
            if let Ok(skel) = decompile::render_class_skeleton(&abc, instance) {
                assert!(skel.contains("class ") || skel.contains("interface "));
                total_decompiled += 1;
            }
        }
    }
    assert!(
        total_classes > 0,
        "ATV megafile ABC must define at least one class"
    );
    assert!(
        total_opcodes > 0,
        "ATV megafile ABC must disassemble to a non-zero opcode stream"
    );
    assert!(
        total_decompiled > 0,
        "ATV megafile ABC must render at least one class skeleton"
    );
}

#[test]
fn corpus_wide_real_abc_parses_and_disassembles() {
    let Some(totals): Option<CorpusTotals> = parse_corpus() else {
        return;
    };
    assert!(
        totals.files_with_abc >= 3,
        "expected multiple AS3-bearing fixtures, got {}",
        totals.files_with_abc
    );
    assert!(
        totals.abc_blobs >= totals.files_with_abc,
        "every ABC-bearing file must yield at least one parsed blob"
    );
    assert!(
        totals.instances > 0,
        "real corpus must define classes across DoABC tags, got {}",
        totals.instances
    );
    assert!(
        totals.opcodes > 0,
        "real corpus must disassemble to a non-zero opcode stream, got {}",
        totals.opcodes
    );
    assert!(
        totals.decompiled_classes > 0,
        "real corpus must render at least one class skeleton, got {}",
        totals.decompiled_classes
    );
    assert!(
        totals.methods > 0,
        "real corpus must declare methods across DoABC tags, got {}",
        totals.methods
    );
}

#[test]
fn rejects_truncated_real_swf() {
    let Some(mut bytes): Option<Vec<u8>> = load_fixture("A-Blast_Liberation.swf") else {
        return;
    };
    bytes.truncate(8);
    let _ = swf::parse(&bytes).expect_err("must fail on truncated body");
}

#[test]
fn rejects_corrupted_magic_signature() {
    let Some(mut bytes): Option<Vec<u8>> = load_fixture("3D_Frogger.swf") else {
        return;
    };
    bytes[0] = b'X';
    let err: disrobe_pass_as3::Error = swf::parse(&bytes).expect_err("must reject bad magic");
    let msg: String = err.to_string();
    assert!(msg.contains("DR-AS3") || msg.contains("signature") || msg.contains("Bad"));
}
