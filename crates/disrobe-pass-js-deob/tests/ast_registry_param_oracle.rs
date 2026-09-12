#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::unminify_ast;

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

fn harness(program: &str, tail: &str) -> String {
    format!(
        r#"var __out=[];var print=function(value){{__out.push(String(value));}};var __modules={{2:{{sum:function(left,right){{return left+right;}}}}}};var __require=function(id){{return __modules[id==="./math-utils"?2:id];}};var __webpack_require__=__require;{program}{tail}"#,
    )
}

fn boa_output(program: &str) -> String {
    let mut context: Context = Context::default();
    let source: String = harness(program, "__out.join('\\u0001');");
    context
        .eval(Source::from_bytes(source.as_bytes()))
        .expect("the registry fixture must execute in Boa")
        .as_string()
        .expect("the registry fixture must return a string in Boa")
        .to_std_string_escaped()
}

fn node_output(program: &str) -> String {
    let source: String = harness(program, "process.stdout.write(__out.join('\\u0001'));");
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&source)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the registry semantic reference")
        .expect("the registry semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "node must execute the registry fixture"
    );
    String::from_utf8(output.stdout).expect("Node registry output must be utf-8")
}

fn assert_runtime_parity(original: &str, recovered: &str) {
    let expected: String = node_output(original);
    assert_eq!(boa_output(original), expected);
    assert_eq!(node_output(recovered), expected);
    assert_eq!(boa_output(recovered), expected);
}

#[test]
fn browserify_registry_factory_recovers_runtime_parameter_names() {
    let source: &str = r#"var bundle={1:[function(a,b,c){var d=a("./math-utils");print(d.sum(2,3));},{"./math-utils":2}]};bundle[1][0](__require,{},{});"#;
    let (recovered, _stats) = unminify_ast(source);
    assert!(
        recovered.contains("function(require,module,exports)"),
        "the bounded Browserify factory must expose its runtime parameter roles:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);
}

#[test]
fn browserify_registry_parameter_recovery_is_scope_safe_and_deterministic() {
    let source: &str = r#"const require=0;var bundle={1:[function(a,b,c){print(a("./math-utils").sum(require,2));},{"./math-utils":2}]};bundle[1][0](__require,{},{});"#;
    let (first, _stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);
    assert_eq!(first, second, "registry recovery must be byte-identical");
    assert!(
        first.contains("function(require_1,module,exports)"),
        "the runtime lookup must not capture the outer binding:\n{first}"
    );
    assert!(
        first.contains("require_1(\"./math-utils\").sum(require,2)"),
        "resolved factory references must follow the collision-safe rename:\n{first}"
    );
    assert_runtime_parity(source, &first);
}

#[test]
fn browserify_registry_recovers_each_static_factory() {
    let source: &str = r#"var bundle={1:[function(a,b,c){print(a("./math-utils").sum(2,3));},{"./math-utils":2}],2:[function(d,e,f){print(d("./math-utils").sum(4,5));},{"./math-utils":2}]};bundle[1][0](__require,{},{});bundle[2][0](__require,{},{});"#;
    let (recovered, _stats) = unminify_ast(source);
    assert_eq!(
        recovered
            .matches("function(require,module,exports)")
            .count(),
        2,
        "each proven factory in one registry must recover independently:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);
}

#[test]
fn webpack_registry_factory_recovers_runtime_parameter_names() {
    let source: &str = r#"var runtimeModule={exports:{}};var bundle={1:function(a,b,c){var d=c("./math-utils");a.exports=d.sum(6,7);b.answer=a.exports;print(b.answer);}};bundle[1](runtimeModule,runtimeModule.exports,__webpack_require__);"#;
    let (first, _stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);
    assert_eq!(first, second, "registry recovery must be byte-identical");
    assert!(
        first.contains("function(module,exports,require)"),
        "the bounded Webpack factory must expose its runtime parameter roles:\n{first}"
    );
    assert!(
        first.contains("require(\"./math-utils\")"),
        "resolved runtime lookups must follow the recovered require binding:\n{first}"
    );
    assert_runtime_parity(source, &first);

    let collision: &str = r#"const module=1;var runtimeModule={exports:{}};var bundle={1:function(a,b,c){a.exports=c("./math-utils").sum(module,4);b.answer=a.exports;print(b.answer);}};bundle[1](runtimeModule,runtimeModule.exports,__webpack_require__);"#;
    let (collision_recovered, _) = unminify_ast(collision);
    assert!(
        collision_recovered.contains("function(module_1,exports,require)"),
        "runtime parameter recovery must not capture an outer module binding:\n{collision_recovered}"
    );
    assert_runtime_parity(collision, &collision_recovered);

    let near_misses: [&str; 3] = [
        r#"var runtimeModule={exports:{}};var callbacks={1:function(a,b,c){a.exports=c("./math-utils");b.answer=a.exports;}};callbacks[1](runtimeModule,runtimeModule.exports,callback);"#,
        r#"var bundle={entry:function(a,b,c){var d=c("./math-utils");print(d.sum(6,7));}};bundle.entry({}, {}, __webpack_require__);"#,
        r#"var bundle={1:function(a,b,c){with({}){print(c("./math-utils").sum(6,7));}}};bundle[1]({}, {}, __require);"#,
    ];
    for near_miss in near_misses {
        let (recovered, _) = unminify_ast(near_miss);
        assert!(
            !recovered.contains("module,exports,require"),
            "unproven Webpack factories must remain untouched:\n{recovered}"
        );
    }
}

#[test]
fn webpack_registry_factory_recovers_roles_in_nonstandard_parameter_order() {
    let fixtures: [(&str, &str); 2] = [
        (
            r#"var runtimeModule={exports:{}};var bundle={1:function(a,b,c){var d=a("./math-utils");b.exports=d.sum(6,7);c.answer=b.exports;print(c.answer);}};bundle[1](__webpack_require__,runtimeModule,runtimeModule.exports);"#,
            "function(require,module,exports)",
        ),
        (
            r#"var runtimeModule={exports:{}};var bundle={1:function(a,b,c){var d=b("./math-utils");c.exports=d.sum(6,7);a.answer=c.exports;print(a.answer);}};bundle[1](runtimeModule.exports,__webpack_require__,runtimeModule);"#,
            "function(exports,require,module)",
        ),
    ];
    for (source, signature) in fixtures {
        let (first, _stats) = unminify_ast(source);
        let (second, _) = unminify_ast(source);
        assert_eq!(first, second, "role recovery must be byte-identical");
        assert!(
            first.contains(signature),
            "semantic role evidence must override parameter position:\n{first}"
        );
        assert_runtime_parity(source, &first);
    }
}

#[test]
fn webpack_static_cycle_recovers_correlated_factory_roles() {
    let source: &str = r#"const module=99;var bundle={1:function(a,b,c){a.exports=b;b.name="one";b.other=c(2).name;print(b.name+":"+b.other+":"+module);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;},3:function(g,h,i){g.exports=h;h.name="tail";h.other=i(1).name;}};var cache={};function __webpack_require__(id){if(cache[id])return cache[id].exports;var runtimeModule=cache[id]={exports:{}};bundle[id](runtimeModule,runtimeModule.exports,__webpack_require__);return runtimeModule.exports;}__webpack_require__(1);"#;
    let (first, _stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);

    assert_eq!(first, second, "cyclic role recovery must be byte-identical");
    assert_eq!(
        first.matches("function(module_1,exports,require)").count(),
        2,
        "both factories in the statically correlated cycle must recover without capturing the outer module binding:\n{first}"
    );
    assert!(first.contains("require(2).name"));
    assert!(first.contains("require(1).name"));
    assert!(
        first.contains("3:function(g,h,i)"),
        "a one-way caller outside the strongly connected component must remain untouched:\n{first}"
    );
    assert_runtime_parity(source, &first);
}

#[test]
fn webpack_static_cycle_recovers_roles_from_immutable_assigned_dispatchers() {
    let fixtures: [&str; 2] = [
        r#"let unused;const module=99;var bundle={1:function(a,b,c){a.exports=b;b.name="one";b.other=c(2).name;print(b.name+":"+b.other+":"+module);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;}};var cache={};const dispatch=function(id){if(cache[id])return cache[id].exports;var runtimeModule=cache[id]={exports:{}};bundle[id](runtimeModule,runtimeModule.exports,dispatch);return runtimeModule.exports;};dispatch(1);"#,
        r#"const module=99;var bundle={1:function(a,b,c){a.exports=b;b.name="one";b.other=c(2).name;print(b.name+":"+b.other+":"+module);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;}};var cache={};const dispatch=(id)=>{if(cache[id])return cache[id].exports;var runtimeModule=cache[id]={exports:{}};bundle[id](runtimeModule,runtimeModule.exports,dispatch);return runtimeModule.exports;};dispatch(1);"#,
    ];
    for source in fixtures {
        let (first, _stats) = unminify_ast(source);
        let (second, _) = unminify_ast(source);
        assert_eq!(
            first, second,
            "assigned dispatcher recovery must be byte-identical"
        );
        assert_eq!(
            first.matches("function(module_1,exports,require)").count(),
            2,
            "both factories in the assigned-dispatcher cycle must recover without capturing the outer module binding:\n{first}"
        );
        assert_runtime_parity(source, &first);
    }
}

#[test]
fn webpack_assigned_cycle_dispatcher_abstains_without_one_immutable_binding() {
    let sources: [&str; 3] = [
        r#"var bundle={1:function(a,b,c){a.exports=b;b.name="one";b.other=c(2).name;print(b.name+":"+b.other);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;}};var cache={};let dispatch=function(id){if(cache[id])return cache[id].exports;var runtimeModule=cache[id]={exports:{}};bundle[id](runtimeModule,runtimeModule.exports,dispatch);return runtimeModule.exports;};dispatch=dispatch;dispatch(1);"#,
        r#"var bundle={1:function(a,b,c){a.exports=b;b.name="one";b.other=c(2).name;print(b.name+":"+b.other);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;}};var cache={};let dispatch;dispatch=function(id){if(cache[id])return cache[id].exports;var runtimeModule=cache[id]={exports:{}};bundle[id](runtimeModule,runtimeModule.exports,dispatch);return runtimeModule.exports;};dispatch(1);"#,
        r#"var bundle={1:function(a,b,c){a.exports=b;b.name="one";b.other=c(2).name;print(b.name+":"+b.other);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;}};(function(id){var runtimeModule={exports:{}};bundle[id](runtimeModule,runtimeModule.exports,__webpack_require__);return runtimeModule.exports;})(1);"#,
    ];
    for source in sources {
        let (recovered, _stats) = unminify_ast(source);
        assert!(
            recovered.contains("1:function(a,b,c)") && recovered.contains("2:function(d,e,f)"),
            "reassigned or unbound dispatchers must leave the cycle unchanged:\n{recovered}"
        );
        assert_runtime_parity(source, &recovered);
    }
}

#[test]
fn webpack_cycle_abstains_on_dynamic_edges_and_ambiguous_dispatchers() {
    let dynamic_edge: &str = r#"var bundle={1:function(a,b,c){var next=2;a.exports=b;b.name="one";b.other=c(next).name;print(b.name+":"+b.other);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;}};var cache={};function __webpack_require__(id){if(cache[id])return cache[id].exports;var runtimeModule=cache[id]={exports:{}};bundle[id](runtimeModule,runtimeModule.exports,__webpack_require__);return runtimeModule.exports;}__webpack_require__(1);"#;
    let ambiguous_dispatcher: &str = r#"var bundle={1:function(a,b,c){a.exports=b;b.name="one";b.other=c(2).name;print(b.name+":"+b.other);},2:function(d,e,f){d.exports=e;e.name="two";e.other=f(1).name;}};var cache={};function __webpack_require__(id){if(cache[id])return cache[id].exports;var runtimeModule=cache[id]={exports:{}};if(globalThis.__never){bundle[id](__webpack_require__,runtimeModule,runtimeModule.exports);}bundle[id](runtimeModule,runtimeModule.exports,__webpack_require__);return runtimeModule.exports;}__webpack_require__(1);"#;

    for source in [dynamic_edge, ambiguous_dispatcher] {
        let (recovered, _stats) = unminify_ast(source);
        assert!(
            recovered.contains("1:function(a,b,c)") && recovered.contains("2:function(d,e,f)"),
            "dynamic or ambiguous cycle evidence must leave every factory unchanged:\n{recovered}"
        );
        assert_runtime_parity(source, &recovered);
    }
}

#[test]
fn webpack_registry_factory_abstains_when_role_evidence_is_ambiguous() {
    let source: &str = r#"var runtimeModule={exports:{}};var bundle={1:function(a,b,c){a.exports=c("./math-utils");b.answer=a.exports;print(b.answer.sum(2,3));}};bundle[1](runtimeModule,runtimeModule.exports,__webpack_require__);if(globalThis.__never){bundle[1](__webpack_require__,runtimeModule,runtimeModule.exports);}"#;
    let (recovered, _stats) = unminify_ast(source);
    assert!(
        recovered.contains("function(a,b,c)"),
        "conflicting bootstrap-role evidence must leave the factory unchanged:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);
}

#[test]
fn webpack_registry_factory_requires_a_matching_bootstrap_call_and_role_use() {
    let source: &str = r#"var runtimeModule={exports:{}};var bundle={1:function(a,b,c){a.exports=c("./math-utils").sum(2,3);b.answer=a.exports;print(b.answer);},2:function(d,e,f){d.exports=f("./math-utils").sum(4,5);e.answer=d.exports;}};bundle[1](runtimeModule,runtimeModule.exports,__webpack_require__);"#;
    let (recovered, _stats) = unminify_ast(source);
    assert!(recovered.contains("1:function(module,exports,require)"));
    assert!(
        recovered.contains("2:function(d,e,f)"),
        "an uninvoked sibling factory must not inherit another module's runtime proof:\n{recovered}"
    );
    assert_runtime_parity(source, &recovered);

    let unrelated_property: &str = r#"var runtimeModule={exports:{}};var bundle={1:function(a,b,c){a.exports=c("./math-utils").sum(2,3);a.cache=1;print(a.exports);}};bundle[1](runtimeModule,runtimeModule.exports,__webpack_require__);"#;
    let (unchanged, _) = unminify_ast(unrelated_property);
    assert!(
        unchanged.contains("function(a,b,c)"),
        "an unrelated object property must not stand in for exports-role evidence:\n{unchanged}"
    );
    assert_runtime_parity(unrelated_property, &unchanged);
}

#[test]
fn webpack_chunk_registration_factory_recovers_runtime_parameter_names() {
    let source: &str = r#"var runtimeModule={exports:{}};globalThis.webpackChunkexample=[];globalThis.webpackChunkexample.push([[101],{7:function(a,b,c){var d=c("./math-utils");a.exports=d.sum(8,9);b.answer=a.exports;print(b.answer);}}]);globalThis.webpackChunkexample[0][1][7](runtimeModule,runtimeModule.exports,__webpack_require__);"#;
    let (first, _stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);
    assert_eq!(
        first, second,
        "chunk registration recovery must be byte-identical"
    );
    assert!(
        first.contains("function(module,exports,require)"),
        "the bounded Webpack chunk factory must expose its runtime parameter roles:\n{first}"
    );
    assert!(
        first.contains("require(\"./math-utils\")"),
        "resolved chunk runtime lookups must follow the recovered require binding:\n{first}"
    );
    assert_runtime_parity(source, &first);

    let collision: &str = r#"const module=1;var runtimeModule={exports:{}};globalThis.webpackChunkexample=[];globalThis.webpackChunkexample.push([[101],{7:function(a,b,c){a.exports=c("./math-utils").sum(module,4);b.answer=a.exports;print(b.answer);}}]);globalThis.webpackChunkexample[0][1][7](runtimeModule,runtimeModule.exports,__webpack_require__);"#;
    let (collision_recovered, _) = unminify_ast(collision);
    assert!(
        collision_recovered.contains("function(module_1,exports,require)"),
        "chunk runtime parameter recovery must not capture an outer module binding:\n{collision_recovered}"
    );
    assert_runtime_parity(collision, &collision_recovered);

    let near_misses: [&str; 2] = [
        r#"var runtimeModule={exports:{}};var callbacks=[];callbacks.push([[101],{7:function(a,b,c){a.exports=c("./math-utils").sum(8,9);b.answer=a.exports;print(b.answer);}}]);callbacks[0][1][7](runtimeModule,runtimeModule.exports,__webpack_require__);"#,
        r#"var runtimeModule={exports:{}};globalThis.webpackChunkexample=[];globalThis.webpackChunkexample.push([["entry"],{7:function(a,b,c){a.exports=c("./math-utils").sum(8,9);b.answer=a.exports;print(b.answer);}}]);globalThis.webpackChunkexample[0][1][7](runtimeModule,runtimeModule.exports,__webpack_require__);"#,
    ];
    for near_miss in near_misses {
        let (recovered, _) = unminify_ast(near_miss);
        assert!(
            recovered.contains("function(a,b,c)"),
            "only exact numeric Webpack chunk registrations may rename roles:\n{recovered}"
        );
    }
}

#[test]
fn non_static_or_dynamic_registry_factories_abstain() {
    let sources: [&str; 2] = [
        r#"var bundle={1:[function(a,b,c){print(a("./math-utils").sum(2,3));},{"./math-utils":dependency}]};bundle[1][0](__require,{},{});"#,
        r#"var bundle={1:[function(a,b,c){print(eval("a('./math-utils').sum(2,3)"));},{"./math-utils":2}]};bundle[1][0](__require,{},{});"#,
    ];
    for source in sources {
        let (recovered, _stats) = unminify_ast(source);
        assert!(
            recovered.contains("function(a,b,c)"),
            "unproven registry factories must remain untouched:\n{recovered}"
        );
    }
}

#[test]
fn parcel_register_factory_recovers_live_module_and_exports_parameters() {
    let source: &str = r#"var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};(0,globalThis.parcelRequire7a05.register)("entry",function(a,b){a.exports.answer=__require("./math-utils").sum(8,9);b.value=a.exports.answer;print(b.value);});"#;
    let (first, stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);
    assert_eq!(
        first, second,
        "Parcel registry recovery must be byte-identical"
    );
    assert!(
        first.contains("function(module,exports)"),
        "a static Parcel register factory must expose its runtime parameter roles:\n{first}"
    );
    assert!(
        first.contains("module.exports.answer") && first.contains("exports.value"),
        "resolved Parcel factory references must follow both recovered names:\n{first}"
    );
    assert_eq!(stats.parcel_parameters_renamed, 2);
    assert_runtime_parity(source, &first);
}

#[test]
fn direct_parcel_register_factory_recovers_the_same_roles() {
    let source: &str = r#"var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};globalThis.parcelRequire7a05.register("entry",function(a,b){a.exports.answer=__require("./math-utils").sum(6,7);b.value=a.exports.answer;print(b.value);});"#;
    let (first, stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);
    assert_eq!(first, second);
    assert!(first.contains("function(module,exports)"));
    assert!(first.contains("module.exports.answer") && first.contains("exports.value"));
    assert_eq!(stats.parcel_parameters_renamed, 2);
    assert_runtime_parity(source, &first);
}

#[test]
fn immutable_parcel_register_alias_recovers_live_roles_without_capture() {
    let source: &str = r#"const module=10;var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};const r=globalThis.parcelRequire7a05.register;var held={r};r("entry",function(a,b){a.exports.answer=__require("./math-utils").sum(module,4);b.value=a.exports.answer;print(b.value);});(0,r)("secondary",function(c,d){c.exports.answer=__require("./math-utils").sum(module,5);d.value=c.exports.answer;print(d.value);});"#;
    let (first, stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);
    assert_eq!(
        first, second,
        "Parcel alias recovery must be byte-identical"
    );
    assert!(
        first.matches("function(module_1,exports)").count() == 2,
        "an immutable Parcel register alias must expose collision-safe roles:\n{first}"
    );
    assert!(
        first.contains("module_1.exports.answer") && first.contains("sum(module,4)"),
        "the recovered binding and outer collision must remain distinct:\n{first}"
    );
    assert_eq!(stats.parcel_parameters_renamed, 4);
    assert_runtime_parity(source, &first);
}

#[test]
fn parcel_register_variants_recover_static_alias_chains_and_invocations() {
    let source: &str = r#"const module=10;var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};globalThis["parcelRequire7a05"]["register"](7,function(a,b){a.exports.answer=__require("./math-utils").sum(module,2);b.value=a.exports.answer;print(b.value);});const first=globalThis.parcelRequire7a05.register;const second=first;second.call(void 0,"call",function(c,d){c.exports.answer=__require("./math-utils").sum(3,4);d.value=c.exports.answer;print(d.value);});let assigned;assigned=second;assigned.apply(void 0,["apply",function(e,f){e.exports.answer=__require("./math-utils").sum(5,6);f.value=e.exports.answer;print(f.value);}]);(0,assigned)("sequence",function(g,h){g.exports.answer=__require("./math-utils").sum(7,8);h.value=g.exports.answer;print(h.value);});"#;
    let (first, stats) = unminify_ast(source);
    let (second, _) = unminify_ast(source);

    assert_eq!(
        first, second,
        "Parcel variant recovery must be byte-identical"
    );
    assert_eq!(
        first.matches("function(module_1,exports)").count(),
        4,
        "each proven static Parcel registration must expose its live roles:\n{first}"
    );
    assert!(first.contains("sum(module,2)"));
    assert_eq!(stats.parcel_parameters_renamed, 8);
    assert_runtime_parity(source, &first);
}

#[test]
fn parcel_register_variants_refuse_unproven_aliases_and_dynamic_scope() {
    let sources: [&str; 7] = [
        r#"var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};let assigned;assigned=globalThis.parcelRequire7a05.register;assigned=globalThis.parcelRequire7a05.register;assigned("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
        r#"const globalThis={parcelRequire7a05:{register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}}};const first=globalThis["parcelRequire7a05"]["register"];const second=first;second("entry",function(a,b){a.exports.answer=2;b.value=a.exports.answer;print(b.value);});"#,
        r#"globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};globalThis.parcelRequire7a05["reg"+"ister"]("entry",function(a,b){a.exports.answer=3;b.value=a.exports.answer;print(b.value);});"#,
        r#"globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};const register=globalThis.parcelRequire7a05.register;const id="entry";register.call(void 0,id,function(a,b){a.exports.answer=4;b.value=a.exports.answer;print(b.value);});"#,
        r#"globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};const register=globalThis.parcelRequire7a05.register;const args=["entry",function(a,b){a.exports.answer=5;b.value=a.exports.answer;print(b.value);}];register.apply(void 0,args);"#,
        r#"globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};let assigned;assigned=globalThis.parcelRequire7a05.register;eval("assigned=assigned");assigned("entry",function(a,b){a.exports.answer=6;b.value=a.exports.answer;print(b.value);});"#,
        r#"function load(){globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};const register=globalThis.parcelRequire7a05.register;with({}){register("entry",function(a,b){a.exports.answer=7;b.value=a.exports.answer;print(b.value);});}}load();"#,
    ];
    for source in sources {
        let (first, stats) = unminify_ast(source);
        let (second, _) = unminify_ast(source);

        assert_eq!(first, second, "Parcel refusal must be byte-identical");
        assert!(
            first.contains("function(a,b)"),
            "unproven Parcel variants must preserve factory bindings:\n{first}"
        );
        assert_eq!(stats.parcel_parameters_renamed, 0);
        assert_runtime_parity(source, &first);
    }
}

#[test]
fn parcel_register_alias_recovery_rejects_mutation_ambiguity_and_dynamic_scope() {
    let sources: [&str; 7] = [
        r#"var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};let r=globalThis.parcelRequire7a05.register;var held={r};r=function(){};r("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
        r#"var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};var r=globalThis.parcelRequire7a05.register;var r=globalThis.parcelRequire7a05.register;var held={r};r("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
        r#"function load(){var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};const r=globalThis.parcelRequire7a05.register;var held={r};with({}){r("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});}}load();"#,
        r#"var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};let r=globalThis.parcelRequire7a05.register;var held={r};eval("r=function(){}");r("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
        r#"const globalThis={parcelRequire7a05:{register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}}};const r=globalThis.parcelRequire7a05.register;var held={r};r("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
        r"globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};const r=globalThis.parcelRequire7a05.register;var held={r};r(dynamicId,function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});",
        r#"globalThis.otherRuntime={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};const r=globalThis.otherRuntime.register;var held={r};r("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
    ];
    for source in sources {
        let (unchanged, stats) = unminify_ast(source);
        assert!(
            unchanged.contains("function(a,b)"),
            "only a single immutable alias of the unresolved Parcel runtime may rename roles:\n{unchanged}"
        );
        assert_eq!(stats.parcel_parameters_renamed, 0);
    }
}

#[test]
fn parcel_register_recovery_avoids_capture_and_rejects_near_misses() {
    let collision: &str = r#"const module=10;var registry={};globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);registry[id]=runtimeModule.exports;}};(0,globalThis.parcelRequire7a05.register)("entry",function(a,b){a.exports.answer=__require("./math-utils").sum(module,4);b.value=a.exports.answer;print(b.value);});"#;
    let (recovered, _) = unminify_ast(collision);
    assert!(
        recovered.contains("function(module_1,exports)"),
        "Parcel recovery must not capture an outer module binding:\n{recovered}"
    );
    assert!(
        recovered.contains("module_1.exports.answer") && recovered.contains("sum(module,4)"),
        "the collision-safe binding and outer binding must remain distinct:\n{recovered}"
    );
    assert_runtime_parity(collision, &recovered);

    let near_misses: [&str; 4] = [
        r#"var callbacks={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};callbacks.register("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
        r"globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};globalThis.parcelRequire7a05.register(dynamicId,function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});",
        r#"globalThis.parcelRequire7a05={register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}};globalThis.parcelRequire7a05.register("entry",function(a,b){with({}){a.exports.answer=1;b.value=a.exports.answer;print(b.value);}});"#,
        r#"const globalThis={parcelRequire7a05:{register:function(id,factory){var runtimeModule={exports:{}};factory(runtimeModule,runtimeModule.exports);}}};globalThis.parcelRequire7a05.register("entry",function(a,b){a.exports.answer=1;b.value=a.exports.answer;print(b.value);});"#,
    ];
    for source in near_misses {
        let (unchanged, _) = unminify_ast(source);
        assert!(
            unchanged.contains("function(a,b)"),
            "only proven static Parcel register factories may rename roles:\n{unchanged}"
        );
    }
}
