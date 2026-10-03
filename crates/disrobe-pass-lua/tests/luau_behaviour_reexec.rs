#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use disrobe_pass_lua::decompile::{DecompiledChunk, decompile_chunk};
use disrobe_pass_lua::reader::common::{
    LuaChunk, LuaConstant, LuaProto, LuaTemplateScalar, LuaTemplateValue,
};
use disrobe_pass_lua::reader::luau;
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};

const RUN_TIMEOUT: Duration = Duration::from_secs(8);
const GLOBAL_WATCH: &str = "setfenv(1, setmetatable({}, {__index = _G, __newindex = function(t, k, v) print(\"new global\", k) rawset(t, k, v) end}))\n";

const PROGRAMS: &[(&str, &str)] = &[
    (
        "luau_threading",
        include_str!("../../../corpus/lua/behaviour/luau_threading.lua"),
    ),
    (
        "branch_scope",
        include_str!("../../../corpus/lua/behaviour/branch_scope.lua"),
    ),
    (
        "rich_scope",
        include_str!("../../../corpus/lua/behaviour/rich_scope.lua"),
    ),
    (
        "branches",
        include_str!("../../../corpus/lua/behaviour/branches.lua"),
    ),
    (
        "branch_reassign",
        include_str!("../../../corpus/lua/behaviour/branch_reassign.lua"),
    ),
    (
        "compare_select",
        include_str!("../../../corpus/lua/behaviour/compare_select.lua"),
    ),
    (
        "loop_locals",
        include_str!("../../../corpus/lua/behaviour/loop_locals.lua"),
    ),
    (
        "testset_pending",
        include_str!("../../../corpus/lua/behaviour/testset_pending.lua"),
    ),
];

fn luau_tool(stem: &str) -> String {
    let candidates: [String; 2] = [format!("{stem}.exe"), stem.to_owned()];
    for candidate in &candidates {
        let probe: Result<ToolOutput, disrobe_testkit::ToolError> =
            tool_output(CommandSpec::new(candidate.as_str(), RUN_TIMEOUT).arg("--help"));
        if probe.is_ok() {
            return candidate.clone();
        }
    }
    panic!(
        "the Luau behaviour oracle needs Luau 0.725's `{stem}` on PATH and cannot grade without it"
    )
}

fn run(luau: &str, script: &Path) -> Result<String, String> {
    let output: ToolOutput = tool_output(CommandSpec::new(luau, RUN_TIMEOUT).arg(script))
        .map_err(|error: disrobe_testkit::ToolError| error.to_string())?;
    if output.timed_out {
        return Err(format!("timed out after {RUN_TIMEOUT:?}"));
    }
    if !output.success {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).replace("\r\n", "\n"))
}

fn recover(compiler: &str, dir: &Path, name: &str, source: &str) -> DecompiledChunk {
    let src: PathBuf = dir.join(format!("{name}.lua"));
    std::fs::write(&src, source).expect("write the program");
    let compiled: ToolOutput = tool_output(
        CommandSpec::new(compiler, RUN_TIMEOUT)
            .arg("--binary")
            .arg(&src),
    )
    .expect("luau-compile starts");
    assert!(
        compiled.success && !compiled.stdout.is_empty(),
        "{name}: luau-compile --binary compiles the program:\n{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let chunk: LuaChunk = luau::read(&compiled.stdout).expect("parse luau bytecode");
    decompile_chunk(&chunk).expect("decompile luau bytecode")
}

#[test]
fn behaviour_programs_reexecute_identically_through_luau() {
    let compiler: String = luau_tool("luau-compile");
    let interpreter: String = luau_tool("luau");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_lua_luau_behaviour").expect("scratch");
    let dir: &Path = scratch.path();
    let mut diverged: Vec<String> = Vec::new();
    for (name, source) in PROGRAMS {
        let original: PathBuf = dir.join(format!("{name}.orig.lua"));
        std::fs::write(&original, format!("{GLOBAL_WATCH}{source}")).expect("write original");
        let expected: String = run(&interpreter, &original).unwrap_or_else(|error: String| {
            panic!("{name}: the program must run under Luau: {error}")
        });
        let recovered: DecompiledChunk = recover(&compiler, dir, name, source);
        let recovered_path: PathBuf = dir.join(format!("{name}.dec.lua"));
        std::fs::write(
            &recovered_path,
            format!("{GLOBAL_WATCH}{}", recovered.source),
        )
        .expect("write recovered");
        let actual: Result<String, String> = run(&interpreter, &recovered_path);
        if actual.as_deref() != Ok(expected.as_str()) {
            diverged.push(format!(
                "{name}\n--- expected ---\n{expected}--- actual ---\n{}\n--- recovered ---\n{}",
                actual.unwrap_or_else(|error: String| format!("<failed: {error}>")),
                recovered.source
            ));
        }
    }
    assert!(diverged.is_empty(), "{}", diverged.join("\n=====\n"));
}

#[test]
fn a_recovery_that_changes_one_operator_is_caught() {
    let compiler: String = luau_tool("luau-compile");
    let interpreter: String = luau_tool("luau");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_lua_luau_behaviour_mutant")
            .expect("scratch");
    let dir: &Path = scratch.path();
    let source: &str = "local a, b = tonumber(\"3\"), tonumber(\"4\")\nprint(a + b, a * b)\n";
    let recovered: DecompiledChunk = recover(&compiler, dir, "mutant", source);
    let mutated: String = recovered.source.replacen('+', "-", 1);
    assert_ne!(
        mutated, recovered.source,
        "the mutation must change the recovered text"
    );
    let recovered_path: PathBuf = dir.join("mutant.dec.lua");
    std::fs::write(&recovered_path, &recovered.source).expect("write recovered");
    let mutated_path: PathBuf = dir.join("mutant.mut.lua");
    std::fs::write(&mutated_path, &mutated).expect("write mutant");
    assert_eq!(
        run(&interpreter, &recovered_path),
        Ok("7\t12\n".to_owned()),
        "the unmutated recovery re-executes:\n{}",
        recovered.source
    );
    assert_ne!(
        run(&interpreter, &recovered_path),
        run(&interpreter, &mutated_path)
    );
}

#[test]
fn duptable_templates_preserve_scalar_fields_nil_removal_and_independence() {
    let compiler: String = luau_tool("luau-compile");
    let interpreter: String = luau_tool("luau");
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_lua_luau_duptable").expect("scratch");
    let dir: &Path = scratch.path();
    let source: &str = r#"
local function zero_template()
    return { zero_a = 0, zero_b = 0 }
end

local function mixed_template()
    return { number = 7, enabled = true, label = "from_template", removed = nil }
end

local first = mixed_template()
local second = mixed_template()
first.number = 99
first.removed = "only-first"
local zero = zero_template()
print(zero.zero_a, zero.zero_b)
print(first.number, first.enabled, first.label, first.removed)
print(second.number, second.enabled, second.label, second.removed == nil)
"#;
    let recovered: DecompiledChunk = recover(&compiler, dir, "duptable", source);
    let original_path: PathBuf = dir.join("duptable.orig.lua");
    std::fs::write(&original_path, source).expect("write original");
    let recovered_path: PathBuf = dir.join("duptable.dec.lua");
    std::fs::write(&recovered_path, &recovered.source).expect("write recovered");
    let expected: String = run(&interpreter, &original_path).expect("original runtime");
    assert_eq!(
        expected,
        "0\t0\n99\ttrue\tfrom_template\tonly-first\n7\ttrue\tfrom_template\ttrue\n"
    );
    assert_eq!(
        run(&interpreter, &recovered_path),
        Ok(expected),
        "recovered template program:\n{}",
        recovered.source
    );
    let mutated: String = recovered.source.replacen("from_template", "mutation", 1);
    assert_ne!(
        mutated, recovered.source,
        "template string must be recovered"
    );
    let mutated_path: PathBuf = dir.join("duptable.mut.lua");
    std::fs::write(&mutated_path, &mutated).expect("write mutant");
    assert_ne!(
        run(&interpreter, &recovered_path),
        run(&interpreter, &mutated_path),
        "the template-content mutation must change behavior"
    );

    let source_path: PathBuf = dir.join("duptable.source.lua");
    std::fs::write(&source_path, source).expect("write source");
    let compiled: ToolOutput = tool_output(
        CommandSpec::new(&compiler, RUN_TIMEOUT)
            .arg("--binary")
            .arg(&source_path),
    )
    .expect("luau-compile starts");
    assert!(compiled.success, "template fixture compiles");
    let chunk: LuaChunk = luau::read(&compiled.stdout).expect("parse template bytecode");
    let mut templates: Vec<&Arc<[disrobe_pass_lua::reader::common::LuaTableTemplateField]>> =
        Vec::new();
    collect_templates(&chunk.main, &mut templates);
    assert!(templates.iter().any(|fields| {
        fields.len() == 2
            && fields.iter().all(|field| {
                matches!(
                    &field.value,
                    LuaTemplateValue::Scalar(LuaTemplateScalar::Number(value)) if *value == 0.0
                )
            })
    }));
    assert!(templates.iter().any(|fields| {
        fields
            .iter()
            .any(|field| matches!(&field.value, LuaTemplateValue::Nil))
            && fields.iter().any(|field| {
                matches!(
                    &field.value,
                    LuaTemplateValue::Scalar(LuaTemplateScalar::Number(value)) if value.to_bits() == 7.0f64.to_bits()
                )
            })
            && fields.iter().any(|field| {
                matches!(
                    &field.value,
                    LuaTemplateValue::Scalar(LuaTemplateScalar::Bool(true))
                )
            }) && fields.iter().any(|field| {
            matches!(
                &field.value,
                LuaTemplateValue::Scalar(LuaTemplateScalar::Str(value)) if value == "from_template"
            )
        })
    }));
}

fn collect_templates<'a>(
    proto: &'a LuaProto,
    templates: &mut Vec<&'a Arc<[disrobe_pass_lua::reader::common::LuaTableTemplateField]>>,
) {
    for constant in &proto.constants {
        if let LuaConstant::TableTemplate(fields) = constant {
            templates.push(fields);
        }
    }
    for child in &proto.protos {
        collect_templates(child, templates);
    }
}
