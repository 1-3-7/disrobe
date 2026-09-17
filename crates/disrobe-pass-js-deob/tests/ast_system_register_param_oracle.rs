#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_core::{Artifact, Rung, chain::Pass};
use disrobe_pass_js_deob::chain_detector::JS_OBF_PASS;
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const FIXTURE: &str = include_str!("fixtures/rollup_system_param/fixture.min.js");
const NAMED_FIXTURE: &str = include_str!("fixtures/babel_system_named_param/fixture.min.js");
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

fn node_output(source: &str) -> Vec<u8> {
    let harness: String = format!(
        r#"const modules={{"@fixture/math-utils":{{sum:(left,right)=>left+right}},"@fixture/difference-math":{{sum:(left,right)=>left-right}},"@fixture/text-format":{{default:value=>`value=${{value}}`}}}};globalThis.System={{register(...args){{const [dependencies,declare]=args.length===3?args.slice(1):args;const registration=declare(()=>{{}},{{id:"fixture"}});registration.setters.forEach((setter,index)=>setter(modules[dependencies[index]]));registration.execute();}}}};{source};process.stdout.write(globalThis.__result);"#
    );
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&harness)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("Node is required for the System.register semantic reference")
        .expect("the System.register semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "Node must execute the System.register fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn node_live_outputs(source: &str) -> Vec<u8> {
    let harness: String = format!(
        r#"let captured;globalThis.System={{register(...args){{const [dependencies,declare]=args.length===3?args.slice(1):args;captured={{dependencies,registration:declare(()=>{{}},{{id:"fixture"}})}};}}}};{source};const initial=[{{sum:(left,right)=>left+right}},{{default:value=>`value=${{value}}`}}];const updated=[{{sum:(left,right)=>left-right}},{{default:value=>`updated=${{value}}`}}];captured.registration.setters.forEach((setter,index)=>setter(initial[index]));captured.registration.execute();const first=globalThis.__result;captured.registration.setters.forEach((setter,index)=>setter(updated[index]));captured.registration.execute();process.stdout.write(`${{first}}|${{globalThis.__result}}`);"#
    );
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&harness)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("Node is required for the System.register live-update reference")
        .expect("the System.register live-update reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "Node must execute both setter updates: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

fn compact(source: &str) -> String {
    source
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect()
}

#[test]
fn registered_pass_recovers_rollup_system_setter_parameter_names() {
    assert!(FIXTURE.len() > 200);
    assert_eq!(FIXTURE.lines().count(), 1);
    let original_stdout: Vec<u8> = node_output(FIXTURE);
    let mutated: String = FIXTURE.replacen("@fixture/math-utils", "@fixture/difference-math", 1);
    assert_ne!(node_output(&mutated), original_stdout);

    let (_direct, direct_stats): (String, AstUnminifyStats) = unminify_ast(FIXTURE);
    assert_eq!(direct_stats.system_register_parameters_renamed, 2);
    assert_eq!(direct_stats.amd_parameters_renamed, 0);
    assert_eq!(direct_stats.commonjs_parameters_renamed, 0);
    assert_eq!(direct_stats.global_iife_parameters_renamed, 0);

    let input: Artifact = Artifact::new(Rung::Raw, FIXTURE.as_bytes().to_vec(), [0x58_u8; 32]);
    let recovered: Artifact = JS_OBF_PASS
        .run(&input)
        .expect("the registered js.deob pass must recover the real System.register fixture");
    let recovered_source: String = String::from_utf8(recovered.envelope)
        .expect("the recovered JavaScript surface must remain UTF-8");
    let compact_recovered: String = compact(&recovered_source);
    assert!(compact_recovered.contains("function(mathUtils){t=mathUtils.sum}"));
    assert!(compact_recovered.contains("function(textFormat){e=textFormat.default}"));
    assert_eq!(node_output(&recovered_source), original_stdout);
    assert_eq!(node_live_outputs(FIXTURE), b"value=42|updated=-2");
    assert_eq!(
        node_live_outputs(&recovered_source),
        node_live_outputs(FIXTURE)
    );

    let repeated: Artifact = JS_OBF_PASS
        .run(&input)
        .expect("the registered pass must deterministically recover the same registry module");
    assert_eq!(repeated.envelope, recovered_source.as_bytes());
}

#[test]
fn registered_pass_recovers_named_system_setter_parameter_names() {
    assert_eq!(NAMED_FIXTURE.len(), 232);
    assert_eq!(NAMED_FIXTURE.lines().count(), 1);
    let original_stdout: Vec<u8> = node_output(NAMED_FIXTURE);
    let mutated: String =
        NAMED_FIXTURE.replacen("@fixture/math-utils", "@fixture/difference-math", 1);
    assert_ne!(node_output(&mutated), original_stdout);

    let (_direct, direct_stats): (String, AstUnminifyStats) = unminify_ast(NAMED_FIXTURE);
    assert_eq!(direct_stats.system_register_parameters_renamed, 2);
    assert_eq!(direct_stats.amd_parameters_renamed, 0);
    assert_eq!(direct_stats.commonjs_parameters_renamed, 0);
    assert_eq!(direct_stats.global_iife_parameters_renamed, 0);

    let input: Artifact =
        Artifact::new(Rung::Raw, NAMED_FIXTURE.as_bytes().to_vec(), [0x59_u8; 32]);
    let recovered: Artifact = JS_OBF_PASS
        .run(&input)
        .expect("the registered js.deob pass must recover the named registry module");
    let recovered_source: String = String::from_utf8(recovered.envelope)
        .expect("the recovered named registry module must remain UTF-8");
    let compact_recovered: String = compact(&recovered_source);
    assert!(compact_recovered.contains("System.register(\"fixture/main\",["));
    assert!(compact_recovered.contains("function(mathUtils){u=mathUtils.sum}"));
    assert!(compact_recovered.contains("function(textFormat){i=textFormat.default}"));
    assert_eq!(node_output(&recovered_source), original_stdout);
    assert_eq!(
        node_live_outputs(&recovered_source),
        node_live_outputs(NAMED_FIXTURE)
    );
    let repeated: Artifact = JS_OBF_PASS
        .run(&input)
        .expect("the registered pass must deterministically recover the named registry module");
    assert_eq!(repeated.envelope, recovered_source.as_bytes());
}

#[test]
fn system_register_recovery_is_transactional_and_fail_closed() {
    let accepted: &str = r#"System.register(["@fixture/math-utils","side","noop"],function(){return{setters:[function(a){sink=a.sum},null,function(){}],execute:function(){}}});"#;
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(accepted);
    assert_eq!(stats.system_register_parameters_renamed, 1);
    assert!(compact(&recovered).contains("function(mathUtils){sink=mathUtils.sum}"));

    let mixed: &str = r#"System.register(["@fixture/math-utils"],function(){return{setters:[function(a){sink=a.sum}],execute:function(){}}});System.register(["bad"],function(){return{setters:[a=>sink=a],execute:function(){}}});"#;
    let (mixed_recovered, mixed_stats): (String, AstUnminifyStats) = unminify_ast(mixed);
    assert_eq!(mixed_stats.system_register_parameters_renamed, 1);
    assert!(compact(&mixed_recovered).contains("function(mathUtils){sink=mathUtils.sum}"));
    assert!(mixed_recovered.contains("a=>sink=a"));

    let suffix_transaction: &str = r#"const mathUtils=0;System.register(["@fixture/math-utils","bad"],function(){return{setters:[function(a){sink=a.sum},a=>sink=a],execute:function(){}}});System.register(["@fixture/math-utils"],function(){return{setters:[function(a){sink=a.sum}],execute:function(){}}});"#;
    let (suffix_recovered, suffix_stats): (String, AstUnminifyStats) =
        unminify_ast(suffix_transaction);
    assert_eq!(suffix_stats.system_register_parameters_renamed, 1);
    assert!(compact(&suffix_recovered).contains("function(mathUtils_1){sink=mathUtils_1.sum}"));
    assert!(!suffix_recovered.contains("mathUtils_2"));

    let excluded: [&str; 14] = [
        r#"const System={register(){}};System.register(["dep"],function(){return{setters:[function(a){sink=a}],execute:function(){}}});"#,
        r#"System["register"](["dep"],function(){return{setters:[function(a){sink=a}],execute:function(){}}});"#,
        r#"System.register(name,["dep"],function(){return{setters:[function(a){sink=a}],execute:function(){}}});"#,
        r#"System.register("name",["dep"],function(e){return{setters:[function(a){sink=a}],execute:function(){}}});"#,
        r#"System.register("name",["dep"],function(e=side(),c){return{setters:[function(a){sink=a}],execute:function(){}}});"#,
        r#"System.register("name",["dep"],function({e},c){return{setters:[function(a){sink=a}],execute:function(){}}});"#,
        r"System.register([dep],function(){return{setters:[function(a){sink=a}],execute:function(){}}});",
        r#"System.register(["dep"],function(){return{setters:[a=>sink=a],execute:function(){}}});"#,
        r#"System.register(["dep"],function(){return{setters:[function(){side()}],execute:function(){}}});"#,
        r#"System.register(["dep"],function(){return{setters:[],execute:function(){}}});"#,
        r#"System.register(["dep"],function(){return{setters:[function(a){a=1}],execute:function(){}}});"#,
        r#"System.register(["dep"],function(){return{setters:[function(a){eval(a)}],execute:function(){}}});"#,
        r#"System.register(["dep"],function(){return{setters:[function(a){sink=a}],execute:async function(){}}});"#,
        r#"System.register(["dep"],function(){return{setters:[function(a){sink=a}],execute:function(){}},tail()});"#,
    ];
    for source in excluded {
        let (output, output_stats): (String, AstUnminifyStats) = unminify_ast(source);
        assert_eq!(
            output_stats.system_register_parameters_renamed, 0,
            "{source}"
        );
        assert!(
            !compact(&output).contains("function(dep)"),
            "{source}\n{output}"
        );
    }
}

#[test]
fn registration_ceiling_rolls_back_earlier_edits() {
    let mut source: String = String::from(
        r#"System.register(["@fixture/math-utils"],function(){return{setters:[function(a){sink=a.sum}],execute:function(){}}});"#,
    );
    for _ in 0..4_096 {
        source
            .push_str(r"System.register([],function(){return{setters:[],execute:function(){}}});");
    }
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&source);
    assert_eq!(stats.system_register_parameters_renamed, 0);
    assert_eq!(recovered, source);
}

#[test]
fn dependency_setter_ceiling_rolls_back_earlier_edits() {
    let mut source: String = String::from(
        r#"System.register(["@fixture/math-utils"],function(){return{setters:[function(a){sink=a.sum}],execute:function(){}}});System.register(["#,
    );
    source.push_str(&r#""side","#.repeat(4_096));
    source.push_str(r"],function(){return{setters:[");
    source.push_str(&"null,".repeat(4_096));
    source.push_str(r"],execute:function(){}}});");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&source);
    assert_eq!(stats.system_register_parameters_renamed, 0);
    assert_eq!(recovered, source);
}

#[test]
fn generated_edit_ceiling_rolls_back_earlier_edits() {
    let mut source: String = String::from(
        r#"System.register(["@fixture/math-utils"],function(){return{setters:[function(a){sink=a.sum}],execute:function(){}}});System.register(["oversized"],function(){return{setters:[function(a){"#,
    );
    source.push_str(&"sink(a);".repeat(65_536));
    source.push_str(r"}],execute:function(){}}});");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(&source);
    assert_eq!(stats.system_register_parameters_renamed, 0);
    assert_eq!(recovered, source);
}
