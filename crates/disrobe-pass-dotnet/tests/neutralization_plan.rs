#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use disrobe_pass_dotnet::cil::{MethodBody, OperandValue, parse_method_body};
use disrobe_pass_dotnet::metadata::{MetadataRoot, parse_metadata_root};
use disrobe_pass_dotnet::model::{AssemblyModel, MethodModel, Resolver, TypeModel};
use disrobe_pass_dotnet::pe::{ClrHeader, PeImage, parse, parse_clr_header};
use disrobe_pass_dotnet::unprotect::neutralize::{
    Applied, NeutralizationPlan, NeutralizeError, Patch, Selection, Technique, apply,
};
use disrobe_pass_dotnet::unprotect::{Unprotected, unprotect};

const CONFUSEREX_PLANNED: &[(&str, &[Technique])] = &[
    (
        "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll",
        &[Technique::AntiTamper, Technique::AntiDebug],
    ),
    (
        "../../corpus/dotnet/confuserex/real/GauntletSample.normal.exe",
        &[Technique::AntiDebug],
    ),
    (
        "../../corpus/dotnet/confuserex/real/GauntletSample.maximum.exe",
        &[Technique::AntiDebug],
    ),
];

const BITMONO_PLANNED: &[(&str, &[Technique])] = &[
    (
        "../../corpus/dotnet/obfuscators/bitmono/gauntlet/GauntletBitMono.bitmono.dll",
        &[Technique::AntiDebugBreakpoints, Technique::DotNetHook],
    ),
    (
        "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.Maximum.dll",
        &[Technique::HeaderCorruption],
    ),
    (
        "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.Maximum.dll",
        &[
            Technique::AntiDebugBreakpoints,
            Technique::DotNetHook,
            Technique::HeaderCorruption,
        ],
    ),
];

const CLEAN: &[&str] = &[
    "../../corpus/dotnet/confuserex/real/GauntletSample.clean.exe",
    "../../corpus/dotnet/confuserex/real/BehaviourSuite.clean.exe",
    "../../corpus/dotnet/obfuscators/bitmono/real/GauntletBitMono.clean.dll",
    "../../corpus/dotnet/obfuscators/bitmono/real/BehaviourSuite.clean.dll",
];

fn fixture(rel: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

struct Parsed {
    pe: PeImage,
    resolver: Resolver,
    model: AssemblyModel,
}

fn parse_image(image: &[u8]) -> Parsed {
    let pe: PeImage = parse(image).expect("pe");
    let clr: ClrHeader = parse_clr_header(image, &pe).expect("clr");
    let root: MetadataRoot = parse_metadata_root(image, &pe, &clr).expect("metadata");
    let resolver: Resolver = Resolver::build(image, &pe, &clr, &root).expect("resolver");
    let model: AssemblyModel = resolver.model();
    Parsed {
        pe,
        resolver,
        model,
    }
}

fn plan_of(rel: &str) -> (Vec<u8>, NeutralizationPlan) {
    let (image, _, plan): (Vec<u8>, Vec<u8>, NeutralizationPlan) = plan_and_image_of(rel);
    (image, plan)
}

fn plan_and_image_of(rel: &str) -> (Vec<u8>, Vec<u8>, NeutralizationPlan) {
    let image: Vec<u8> = fixture(rel);
    let unprotected: Unprotected = unprotect(&image)
        .expect("unprotect runs")
        .unwrap_or_else(|| panic!("{rel}: a protector must be detected"));
    (image, unprotected.image, unprotected.report.plan)
}

fn method_by_token(model: &AssemblyModel, token: u32) -> Option<&MethodModel> {
    model
        .types
        .iter()
        .flat_map(|t: &TypeModel| t.methods.iter())
        .find(|m: &&MethodModel| m.token == token)
}

fn body_of(image: &[u8], parsed: &Parsed, token: u32) -> Option<MethodBody> {
    let m: &MethodModel = method_by_token(&parsed.model, token)?;
    let off: usize = parsed.pe.rva_to_offset(m.rva)?;
    parse_method_body(image.get(off..)?).ok()
}

fn references_debugger(image: &[u8], parsed: &Parsed, root: u32) -> bool {
    let mut seen: BTreeSet<u32> = BTreeSet::new();
    let mut work: Vec<u32> = vec![root];
    while let Some(token) = work.pop() {
        if seen.len() > 256 || !seen.insert(token) {
            continue;
        }
        let Some(body): Option<MethodBody> = body_of(image, parsed, token) else {
            continue;
        };
        for ins in &body.instructions {
            let OperandValue::Token(callee) = ins.operand else {
                continue;
            };
            if callee >> 24 == 0x06 {
                work.push(callee);
                continue;
            }
            let name: String = parsed.resolver.resolve_token(callee);
            if name.contains("Debugger::get_IsAttached") || name.contains("Environment::FailFast") {
                return true;
            }
        }
    }
    false
}

fn original_matches_input(image: &[u8], patch: &Patch) {
    let start: usize = usize::try_from(patch.file_offset).unwrap();
    assert_eq!(
        &image[start..start + patch.original.len()],
        patch.original.as_slice(),
        "{}: the plan's original bytes must be the input bytes at the patch offset",
        patch.id
    );
    assert_eq!(
        patch.original.len(),
        patch.replacement.len(),
        "{}",
        patch.id
    );
    assert_eq!(usize::try_from(patch.length).unwrap(), patch.original.len());
    assert_ne!(
        patch.original, patch.replacement,
        "{}: a patch must change bytes",
        patch.id
    );
    assert!(
        !patch.risk.is_empty() && !patch.evidence.detail.is_empty(),
        "{}",
        patch.id
    );
}

#[test]
fn confuserex_plans_name_the_module_initializer_calls_they_remove() {
    for (rel, techniques) in CONFUSEREX_PLANNED {
        // the worker bodies sit in the anti-tamper section, so they are read from the
        // decrypted image while the patch bytes are checked against the input
        let (image, decrypted, plan): (Vec<u8>, Vec<u8>, NeutralizationPlan) =
            plan_and_image_of(rel);
        let parsed: Parsed = parse_image(&decrypted);
        let cctor: u32 = parsed
            .model
            .types
            .iter()
            .find(|t: &&TypeModel| t.full_name == "<Module>")
            .and_then(|t: &TypeModel| t.methods.iter().find(|m: &&MethodModel| m.name == ".cctor"))
            .map(|m: &MethodModel| m.token)
            .expect("module initializer");
        for technique in *techniques {
            assert!(
                plan.count(*technique) > 0,
                "{rel}: expected a {} patch, plan has {:?}",
                technique.label(),
                plan.techniques()
            );
        }
        let debug: &Patch = plan
            .patches
            .iter()
            .find(|p: &&Patch| p.technique == Technique::AntiDebug)
            .expect("anti-debug patch");
        original_matches_input(&image, debug);
        assert_eq!(
            debug.evidence.method_token,
            Some(cctor),
            "{rel}: anti-debug is removed in the module initializer"
        );
        let token_at = |at: usize| -> u32 {
            u32::from_le_bytes([
                debug.original[at],
                debug.original[at + 1],
                debug.original[at + 2],
                debug.original[at + 3],
            ])
        };
        let (callee, opcode): (u32, &str) = if debug.original[0] == 0x28 {
            (token_at(1), "call")
        } else {
            let ldftn: usize = debug
                .original
                .windows(2)
                .position(|w: &[u8]| w == [0xFE, 0x06])
                .unwrap_or_else(|| {
                    panic!("{rel}: the removed span is a call or starts a thread on a worker")
                });
            (token_at(ldftn + 2), "ldftn")
        };
        assert!(
            references_debugger(&decrypted, &parsed, callee),
            "{rel}: the removed worker {callee:#010x} must reach Debugger.IsAttached or Environment.FailFast"
        );
        assert!(
            debug.replacement.iter().all(|b: &u8| *b == 0),
            "{rel}: the span becomes nops"
        );
        let il_offset: u32 = debug.evidence.il_offset.expect("il offset");
        let cctor_body: MethodBody = body_of(&decrypted, &parsed, cctor).expect("cctor body");
        assert!(
            cctor_body.instructions.iter().any(|i| {
                i.offset >= il_offset
                    && i.offset < il_offset + debug.length
                    && i.name == opcode
                    && i.operand == OperandValue::Token(callee)
            }),
            "{rel}: the evidence span at {il_offset:#x} must hold the {opcode} of the worker in the initializer"
        );
        if opcode == "ldftn" {
            let patched: Applied = apply(
                &image,
                &plan,
                &Selection::Only(BTreeSet::from([debug.id.clone()])),
            )
            .expect("applies");
            let patched_parsed: Parsed = parse_image(&patched.bytes);
            let after: MethodBody = body_of(&patched.bytes, &patched_parsed, cctor)
                .expect("patched initializer parses");
            assert!(
                !after
                    .instructions
                    .iter()
                    .any(|i| i.name == "ldftn" && i.operand == OperandValue::Token(callee)),
                "{rel}: after the patch the initializer no longer references the worker"
            );
        }
        for patch in &plan.patches {
            original_matches_input(&image, patch);
        }
        if techniques.contains(&Technique::AntiTamper) {
            let section: &Patch = plan
                .patches
                .iter()
                .find(|p: &&Patch| {
                    p.technique == Technique::AntiTamper && p.evidence.method_token.is_none()
                })
                .expect("anti-tamper section patch");
            assert!(
                section.original.len() > 1024,
                "{rel}: the section patch covers the encrypted bodies"
            );
            assert!(
                plan.patches
                    .iter()
                    .any(|p: &Patch| p.technique == Technique::AntiTamper
                        && p.evidence.method_token == Some(cctor)),
                "{rel}: the initializer call is removed with the section"
            );
        }
    }
}

#[test]
fn bitmono_plans_cover_timing_checks_hooks_and_headers() {
    for (rel, techniques) in BITMONO_PLANNED {
        let (image, plan): (Vec<u8>, NeutralizationPlan) = plan_of(rel);
        for technique in *techniques {
            assert!(
                plan.count(*technique) > 0,
                "{rel}: expected a {} patch, plan has {:?}",
                technique.label(),
                plan.techniques()
            );
        }
        for patch in &plan.patches {
            original_matches_input(&image, patch);
        }
        let applied: Applied =
            apply(&image, &plan, &Selection::All).expect("the plan applies to its own input");
        assert_eq!(
            applied.report.applied.len(),
            plan.patches.len(),
            "{rel}: {:?}",
            applied.report.refused
        );
        let parsed: Parsed = parse_image(&applied.bytes);
        let timing: Vec<&Patch> = plan
            .patches
            .iter()
            .filter(|p: &&Patch| p.technique == Technique::AntiDebugBreakpoints)
            .collect();
        for patch in &timing {
            assert!(
                patch.replacement.iter().all(|b: &u8| *b == 0),
                "{}",
                patch.id
            );
            let token: u32 = patch.evidence.method_token.expect("method");
            let body: MethodBody =
                body_of(&applied.bytes, &parsed, token).expect("patched body parses");
            let il_offset: u32 = patch.evidence.il_offset.expect("il offset");
            let nops: usize = body
                .instructions
                .iter()
                .filter(|i| {
                    i.offset >= il_offset && i.offset < il_offset + patch.length && i.name == "nop"
                })
                .count();
            assert_eq!(
                nops,
                usize::try_from(patch.length).unwrap(),
                "{}: every removed byte decodes as nop",
                patch.id
            );
        }
        let redirected: Vec<&Patch> = plan
            .patches
            .iter()
            .filter(|p: &&Patch| p.technique == Technique::DotNetHook && p.length == 4)
            .collect();
        assert!(
            !redirected.is_empty(),
            "{rel}: hooked call sites are redirected"
        );
        for patch in &redirected {
            let dummy: u32 = u32::from_le_bytes(patch.original.clone().try_into().unwrap());
            let target: u32 = u32::from_le_bytes(patch.replacement.clone().try_into().unwrap());
            let dummy_body: MethodBody = body_of(&image, &parsed, dummy).expect("dummy body");
            assert!(
                dummy_body
                    .instructions
                    .iter()
                    .filter(|i| i.name != "nop")
                    .count()
                    <= 2,
                "{}: the original callee {dummy:#010x} is a hook dummy",
                patch.id
            );
            let dummy_sig = method_by_token(&parsed.model, dummy)
                .expect("dummy")
                .signature
                .clone();
            let target_method: &MethodModel =
                method_by_token(&parsed.model, target).expect("target exists");
            assert!(
                target_method.signature == dummy_sig || target_method.signature.has_this,
                "{}: the redirected target {target:#010x} carries the dummy's signature",
                patch.id
            );
        }
        let again: Unprotected = unprotect(&applied.bytes)
            .expect("unprotect runs on the neutralized copy")
            .expect("the protector is still recognised");
        assert_eq!(
            again.report.plan.count(Technique::AntiDebugBreakpoints),
            0,
            "{rel}: once applied, no timing check remains to plan"
        );
        assert_eq!(
            again.report.plan.count(Technique::HeaderCorruption),
            0,
            "{rel}: headers are whole after apply"
        );
    }
}

#[test]
fn clean_counterparts_plan_nothing() {
    for rel in CLEAN {
        let image: Vec<u8> = fixture(rel);
        let plan: NeutralizationPlan = unprotect(&image)
            .expect("unprotect runs")
            .map_or_else(NeutralizationPlan::default, |u: Unprotected| u.report.plan);
        assert!(
            plan.is_empty(),
            "{rel}: a clean build gets no patch, got {:?}",
            plan.techniques()
        );
    }
}

#[test]
fn a_changed_original_byte_is_refused_by_name() {
    let (image, plan): (Vec<u8>, NeutralizationPlan) =
        plan_of("../../corpus/dotnet/confuserex/real/GauntletSample.normal.exe");
    let first: &Patch = plan.patches.first().expect("a patch");
    let mut mutated: Vec<u8> = image.clone();
    let start: usize = usize::try_from(first.file_offset).unwrap();
    mutated[start + 1] ^= 0x5A;
    let only: Selection = Selection::Only(BTreeSet::from([first.id.clone()]));
    let outcome: Applied =
        apply(&mutated, &plan, &only).expect("a declined-or-refused plan still reports");
    assert!(outcome.report.applied.is_empty());
    assert_eq!(outcome.report.refused.len(), 1);
    assert_eq!(outcome.report.refused[0].id, first.id);
    assert!(
        outcome.report.refused[0].reason.contains("differ"),
        "{}",
        outcome.report.refused[0].reason
    );
    assert_eq!(outcome.bytes, mutated, "a refused patch changes nothing");
    let all: Result<Applied, NeutralizeError> = apply(
        &mutated,
        &NeutralizationPlan {
            patches: vec![first.clone()],
        },
        &Selection::All,
    );
    assert!(matches!(all, Err(NeutralizeError::NothingApplied(_))));
    let pristine: Applied = apply(&image, &plan, &Selection::All).expect("applies");
    assert_eq!(pristine.report.applied.len(), plan.patches.len());
    let declined: Applied =
        apply(&image, &plan, &Selection::Only(BTreeSet::new())).expect("declining is allowed");
    assert_eq!(declined.bytes, image);
    assert_eq!(declined.report.declined.len(), plan.patches.len());
    let again: Unprotected = unprotect(&pristine.bytes)
        .expect("runs")
        .expect("still ConfuserEx");
    assert_eq!(
        again.report.plan.count(Technique::AntiDebug),
        0,
        "the removed initializer call is not planned twice"
    );
}
