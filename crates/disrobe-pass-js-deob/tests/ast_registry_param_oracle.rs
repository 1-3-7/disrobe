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
