#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::time::Instant;

use disrobe_core::chain::metadata_keys::keys::CONTAINER_REFUSALS_KEY;
use disrobe_core::chain::state_machine::{ChainConfig, ChainDriver, ChainPlan, PassRunner};
use disrobe_core::chain::{
    ChainSpec, DetectorPick, Node, OutputKind, PassRegistry, PassRunOutcome, RecoveryStatus,
    status_from_node, tier_from_node,
};
use disrobe_core::pass::PassContext;
use disrobe_core::recovery::ConfidenceTier;
use disrobe_core::{Artifact, Rung};
use disrobe_pass_py_decompile::chain_detector::{PASS_ID, PY_DECOMPILE_PASS};
use disrobe_pass_py_decompile::{NativeDecompile, decompile_pyc};
use disrobe_py_marshal::{CodeObject, Object, PycFile, read_pyc, write_pyc};

const STUBBED_MODULE: &[u8] = include_bytes!(
    "../../../corpus/python/decompile/playground/__pycache__/edge_cases.cpython-314.pyc"
);
const DIRECT_MODULE: &[u8] = include_bytes!(
    "../../../corpus/python/decompile/playground/__pycache__/edge_cases_3_12.cpython-312.pyc"
);
const UNRECOVERABLE_SCOPE: &str = "multi_with_sequential";

#[derive(Debug)]
struct RealRunner;

impl PassRunner for RealRunner {
    fn run(
        &self,
        pick: &DetectorPick,
        bytes: Vec<u8>,
        _config: &ChainConfig,
        path_hint: Option<&str>,
    ) -> Result<PassRunOutcome, String> {
        let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
        let started: Instant = Instant::now();
        let context: PassContext<'_> = PassContext {
            path_hint,
            i_have_authorization: false,
        };
        let output: Artifact = pick
            .pass
            .run_with_context(&artifact, context)
            .map_err(|error: disrobe_core::error::CoreError| error.to_string())?;
        let kind: OutputKind = pick.pass.output_kind(&output);
        let refusals: Vec<String> = pick
            .pass
            .chain_refusals(&artifact)
            .map_err(|error: disrobe_core::error::CoreError| error.to_string())?;
        let mut metadata: BTreeMap<String, String> = BTreeMap::new();
        if !refusals.is_empty() {
            metadata.insert(
                CONTAINER_REFUSALS_KEY.name().to_owned(),
                serde_json::to_string(&refusals)
                    .map_err(|error: serde_json::Error| error.to_string())?,
            );
        }
        Ok(PassRunOutcome {
            output_bytes: output.envelope,
            kind,
            duration: started.elapsed(),
            metadata,
            children: Vec::new(),
        })
    }
}

fn decompile_node(pyc: &[u8]) -> Node {
    let mut registry: PassRegistry = PassRegistry::new();
    registry.register(&PY_DECOMPILE_PASS);
    let runner: RealRunner = RealRunner;
    let driver: ChainDriver<'_, RealRunner> =
        ChainDriver::new(&registry, &runner, ChainConfig::default());
    let plan: ChainPlan = driver.run(pyc.to_vec(), &ChainSpec::Auto { cap: 4 }, None);
    plan.nodes
        .into_iter()
        .find(|node: &Node| node.pass_id.as_deref() == Some(PASS_ID))
        .expect("the chain must route the pyc to py.decompile")
}

fn is_named(code: &CodeObject, name: &str) -> bool {
    matches!(
        &code.name,
        Object::String { value, .. } | Object::Unicode { value, .. } | Object::ShortAscii { value, .. }
            if value == name
    )
}

fn named_scope<'a>(code: &'a CodeObject, name: &str) -> Option<&'a CodeObject> {
    code.consts
        .iter()
        .find_map(|constant: &Object| match constant {
            Object::Code(nested) if is_named(nested, name) => Some(nested.as_ref()),
            Object::Code(nested) => named_scope(nested, name),
            _ => None,
        })
}

fn strip_named_scope_handlers(code: &mut CodeObject, name: &str) -> bool {
    code.consts
        .iter_mut()
        .any(|constant: &mut Object| match constant {
            Object::Code(nested) if is_named(nested, name) => {
                nested.exceptiontable.clear();
                true
            }
            Object::Code(nested) => strip_named_scope_handlers(nested, name),
            _ => false,
        })
}

fn stubbed_module_pyc() -> Vec<u8> {
    let mut pyc: PycFile = read_pyc(STUBBED_MODULE).expect("the tracked 3.14 fixture must parse");
    let Object::Code(module) = &mut pyc.code else {
        panic!("the tracked 3.14 fixture must hold a module code object");
    };
    assert!(
        strip_named_scope_handlers(module, UNRECOVERABLE_SCOPE),
        "the fixture must define {UNRECOVERABLE_SCOPE}"
    );
    write_pyc(&pyc).expect("the stripped module must marshal")
}

fn unrecoverable_module_pyc() -> Vec<u8> {
    let stubbed: Vec<u8> = stubbed_module_pyc();
    let pyc: PycFile = read_pyc(&stubbed).expect("the stripped module must parse");
    let Object::Code(module) = &pyc.code else {
        panic!("the stripped module must hold a module code object");
    };
    let scope: CodeObject = named_scope(module, UNRECOVERABLE_SCOPE)
        .unwrap_or_else(|| panic!("the fixture must define {UNRECOVERABLE_SCOPE}"))
        .clone();
    write_pyc(&PycFile {
        header: pyc.header,
        code: Object::Code(Box::new(scope)),
    })
    .expect("the promoted scope must marshal")
}

#[test]
fn an_unrecoverable_module_falls_back_to_disassembly_with_zero_confidence() {
    let pyc: Vec<u8> = unrecoverable_module_pyc();
    let result: NativeDecompile = decompile_pyc(&pyc).expect("the promoted pyc must load");
    assert!(
        result.is_disasm_fallback(),
        "{UNRECOVERABLE_SCOPE} as a module body must refuse source recovery; got:\n{}",
        result.source
    );
    assert!(!result.recovered_directly);
    assert!(
        result.source_confidence() < f64::EPSILON,
        "a disassembly listing is not recovered source: {}",
        result.source_confidence()
    );
}

#[test]
fn a_disassembly_fallback_is_a_report_and_never_tiers_semantic() {
    let node: Node = decompile_node(&unrecoverable_module_pyc());
    assert!(
        matches!(
            node.output_kind,
            Some(OutputKind::Report {
                format_tag: "python-disassembly",
                ..
            })
        ),
        "the disassembly fallback must not be labelled python source: {:?}",
        node.output_kind
    );
    assert_ne!(tier_from_node(&node), ConfidenceTier::Semantic);
}

#[test]
fn a_directly_recovered_module_stays_python_source_and_tiers_semantic() {
    let node: Node = decompile_node(DIRECT_MODULE);
    assert!(
        matches!(node.output_kind, Some(OutputKind::Source { .. })),
        "{:?}",
        node.output_kind
    );
    assert_eq!(tier_from_node(&node), ConfidenceTier::Semantic);
}

#[test]
fn a_module_with_a_stubbed_nested_scope_is_not_reported_as_direct_recovery() {
    let result: NativeDecompile =
        decompile_pyc(&stubbed_module_pyc()).expect("the stripped module must decompile");
    assert!(
        result.fallback_reason.is_none(),
        "the module itself recovers; only a nested scope is refused: {:?}",
        result.fallback_reason
    );
    assert!(
        result
            .source
            .contains(&format!("def {UNRECOVERABLE_SCOPE}(")),
        "{}",
        result.source
    );
    assert!(
        result.source.contains("decompile-error:"),
        "{}",
        result.source
    );
    assert!(
        !result.recovered_directly,
        "a module with a stubbed nested body must not report direct recovery"
    );
    assert_eq!(result.stubbed_scopes, 1);
    let confidence: f64 = result.source_confidence();
    assert!(confidence > 0.0 && confidence < 1.0, "{confidence}");
}

#[test]
fn a_module_with_a_stubbed_nested_scope_tiers_partial_in_the_chain() {
    let node: Node = decompile_node(&stubbed_module_pyc());
    assert!(
        matches!(node.output_kind, Some(OutputKind::Source { .. })),
        "{:?}",
        node.output_kind
    );
    let refusals: &str = node
        .metadata
        .get(CONTAINER_REFUSALS_KEY.name())
        .map_or("", String::as_str);
    assert!(
        refusals.contains("DR-PYDEC-0913") && refusals.contains("1 of "),
        "the stubbed scope must be reported: {:?}",
        node.metadata
    );
    assert_eq!(tier_from_node(&node), ConfidenceTier::Partial);
    assert_eq!(status_from_node(&node), RecoveryStatus::Incomplete);
    let direct: Node = decompile_node(DIRECT_MODULE);
    assert!(!direct.metadata.contains_key(CONTAINER_REFUSALS_KEY.name()));
}

#[test]
fn a_fully_recovered_module_reports_no_stubs_and_full_confidence() {
    let result: NativeDecompile =
        decompile_pyc(DIRECT_MODULE).expect("the tracked 3.12 fixture must decompile");
    assert!(result.recovered_directly, "{:?}", result.fallback_reason);
    assert_eq!(result.stubbed_scopes, 0);
    assert!((result.source_confidence() - 1.0).abs() < f64::EPSILON);
}
