#![allow(clippy::expect_used, clippy::panic)]

mod common;

use disrobe_core::{Artifact, Rung, chain::Pass};
use disrobe_pass_js_deob::chain_detector::JS_OBF_PASS;
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};
use sha2::{Digest, Sha256};

const FIXTURE: &str = include_str!("fixtures/rollup_system_param/fixture.min.js");
const FIXTURE_SHA256: &str = "38ec01876c2ba99ed64c8669d74e88e300f9bb9d1d09857f34221f768c4f58bd";
const ROLLUP_ENTRY: &str = include_str!("fixtures/rollup_system_param/entry.js");
const ROLLUP_ENTRY_SHA256: &str =
    "a8c01c25bb4aa4999071aa0f1d5db1d5c1eb6dd04282e11187a353aac903474d";
const ROLLUP_OUTPUT: &str = include_str!("fixtures/rollup_system_param/rollup.js");
const ROLLUP_OUTPUT_SHA256: &str =
    "721bbf6542426b955e3da88431757e553ef342b4cb330e4cbfa1479a2bed2d2c";
const NAMED_FIXTURE: &str = include_str!("fixtures/babel_system_named_param/fixture.min.js");
const NAMED_FIXTURE_SHA256: &str =
    "d0917269bffeaddf4021cb3eae4780e433b6a881c34e0412a40f42f9f43cdb3d";
const NAMED_ENTRY: &str = include_str!("fixtures/babel_system_named_param/entry.js");
const NAMED_ENTRY_SHA256: &str = "a8c01c25bb4aa4999071aa0f1d5db1d5c1eb6dd04282e11187a353aac903474d";
const BABEL_OUTPUT: &str = include_str!("fixtures/babel_system_named_param/babel.js");
const BABEL_OUTPUT_SHA256: &str =
    "835884cb556285b0b2f1d0d43665c53d71db3f34f6b51bb9b9bb6fb5def811e8";
const AUTHORED_REFERENCE: &str = r#"System.register(["@fixture/math-utils", "@fixture/text-format"], function () {
    let sum;
    let textFormat;
    return {
        setters: [
            function (mathUtils) { sum = mathUtils.sum; },
            function (format) { textFormat = format.default; },
        ],
        execute: function () { globalThis.__result = textFormat(sum(20, 22)); },
    };
});
"#;
const AUTHORED_REFERENCE_SHA256: &str =
    "8b99d30796b6115c84450e24d2b3d7d53c786ce6a5fe7469f2c65c959c19cd11";
const NAMED_AUTHORED_REFERENCE: &str = r#"System.register("fixture/main", ["@fixture/math-utils", "@fixture/text-format"], function () {
    let sum;
    let textFormat;
    return {
        setters: [
            function (mathUtils) { sum = mathUtils.sum; },
            function (format) { textFormat = format.default; },
        ],
        execute: function () { globalThis.__result = textFormat(sum(20, 22)); },
    };
});
"#;
const NAMED_AUTHORED_REFERENCE_SHA256: &str =
    "4803ad7e24be6b06028d0af2ef8af977d43b437b52da0724fa27eb436360716d";
const REFERENCE_OUTPUT: &str = "value=42";
const DIFFERENCE_OUTPUT: &str = "value=-2";
const REFERENCE_LIVE_OUTPUTS: &str = "value=42|updated=-2";

fn recovered_output(source: &str) -> String {
    let harness: String = format!(
        r#"const modules={{"@fixture/math-utils":{{sum:(left,right)=>left+right}},"@fixture/difference-math":{{sum:(left,right)=>left-right}},"@fixture/text-format":{{default:value=>`value=${{value}}`}}}};globalThis.System={{register(...args){{const [dependencies,declare]=args.length===3?args.slice(1):args;const registration=declare(()=>{{}},{{id:"fixture"}});registration.setters.forEach((setter,index)=>setter(modules[dependencies[index]]));registration.execute();}}}};{source};console.log(globalThis.__result);"#
    );
    common::eval_capture(&harness)
        .expect("bounded Boa evaluation of recovered System.register must finish")
}

fn recovered_live_outputs(source: &str) -> String {
    let harness: String = format!(
        r#"let captured;globalThis.System={{register(...args){{const [dependencies,declare]=args.length===3?args.slice(1):args;captured={{dependencies,registration:declare(()=>{{}},{{id:"fixture"}})}};}}}};{source};const initial=[{{sum:(left,right)=>left+right}},{{default:value=>`value=${{value}}`}}];const updated=[{{sum:(left,right)=>left-right}},{{default:value=>`updated=${{value}}`}}];captured.registration.setters.forEach((setter,index)=>setter(initial[index]));captured.registration.execute();const first=globalThis.__result;captured.registration.setters.forEach((setter,index)=>setter(updated[index]));captured.registration.execute();console.log(`${{first}}|${{globalThis.__result}}`);"#
    );
    common::eval_capture(&harness)
        .expect("bounded Boa evaluation of recovered live setters must finish")
}

fn compact(source: &str) -> String {
    source
        .chars()
        .filter(|character: &char| !character.is_whitespace())
        .collect()
}

fn assert_pinned_artifact(artifact: &str, pinned: &str, label: &str) {
    assert_eq!(
        format!("{:x}", Sha256::digest(artifact.as_bytes())),
        pinned,
        "the {label} is not the one its provenance records, so the pinned reference outputs no \
         longer apply"
    );
}

fn assert_authored_reference(source: &str, hash: &str) {
    assert_eq!(
        format!("{:x}", Sha256::digest(source.as_bytes())),
        hash,
        "the authored System.register reference changed, so its pinned stdout no longer applies"
    );
    assert_eq!(
        recovered_output(source),
        REFERENCE_OUTPUT,
        "the authored System.register reference must produce the pinned stdout"
    );
}

fn assert_authored_entry(entry: &str) {
    assert_eq!(
        entry,
        "import { sum } from \"@fixture/math-utils\";\nimport format from \"@fixture/text-format\";\n\nglobalThis.__result = format(sum(20, 22));\n",
        "the authored entry must remain the independently modeled sum-and-format program"
    );
}

fn assert_mutated_dependency_changes_output(recovered_source: &str) {
    let mutated: String =
        recovered_source.replacen("@fixture/math-utils", "@fixture/difference-math", 1);
    assert_ne!(
        mutated, recovered_source,
        "the recovered registration must still import @fixture/math-utils"
    );
    assert_eq!(
        recovered_output(&mutated),
        DIFFERENCE_OUTPUT,
        "the behavioral comparator must detect a wrong setter dependency"
    );
}

#[test]
fn registered_pass_recovers_rollup_system_setter_parameter_names() {
    assert!(FIXTURE.len() > 200);
    assert_eq!(FIXTURE.lines().count(), 1);
    assert_pinned_artifact(ROLLUP_ENTRY, ROLLUP_ENTRY_SHA256, "authored Rollup entry");
    assert_pinned_artifact(
        ROLLUP_OUTPUT,
        ROLLUP_OUTPUT_SHA256,
        "Rollup compiler output",
    );
    assert_pinned_artifact(FIXTURE, FIXTURE_SHA256, "Rollup/Terser bundle");
    assert_authored_entry(ROLLUP_ENTRY);
    assert_authored_reference(AUTHORED_REFERENCE, AUTHORED_REFERENCE_SHA256);
    assert_eq!(
        recovered_live_outputs(AUTHORED_REFERENCE),
        REFERENCE_LIVE_OUTPUTS,
        "the authored System.register reference must preserve setter liveness"
    );

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
    assert_eq!(recovered_output(&recovered_source), REFERENCE_OUTPUT);
    assert_eq!(
        recovered_live_outputs(&recovered_source),
        REFERENCE_LIVE_OUTPUTS
    );
    assert_mutated_dependency_changes_output(&recovered_source);

    let repeated: Artifact = JS_OBF_PASS
        .run(&input)
        .expect("the registered pass must deterministically recover the same registry module");
    assert_eq!(repeated.envelope, recovered_source.as_bytes());
}

#[test]
fn registered_pass_recovers_named_system_setter_parameter_names() {
    assert_eq!(NAMED_FIXTURE.len(), 232);
    assert_eq!(NAMED_FIXTURE.lines().count(), 1);
    assert_pinned_artifact(NAMED_ENTRY, NAMED_ENTRY_SHA256, "authored Babel entry");
    assert_pinned_artifact(BABEL_OUTPUT, BABEL_OUTPUT_SHA256, "Babel compiler output");
    assert_pinned_artifact(NAMED_FIXTURE, NAMED_FIXTURE_SHA256, "Babel/Terser bundle");
    assert_authored_entry(NAMED_ENTRY);
    assert_authored_reference(NAMED_AUTHORED_REFERENCE, NAMED_AUTHORED_REFERENCE_SHA256);
    assert_eq!(
        recovered_live_outputs(NAMED_AUTHORED_REFERENCE),
        REFERENCE_LIVE_OUTPUTS,
        "the named authored System.register reference must preserve setter liveness"
    );

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
    assert_eq!(recovered_output(&recovered_source), REFERENCE_OUTPUT);
    assert_eq!(
        recovered_live_outputs(&recovered_source),
        REFERENCE_LIVE_OUTPUTS
    );
    assert_mutated_dependency_changes_output(&recovered_source);
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
