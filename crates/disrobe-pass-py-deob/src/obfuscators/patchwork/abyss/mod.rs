use std::collections::BTreeMap;
use std::collections::BTreeSet;

use ruff_python_ast::{
    Expr, ExprCall, ExprName, ExprStringLiteral, ModModule, Stmt, StmtAssign, StmtFunctionDef,
    StmtReturn,
};
use serde_json::Value as Json;

use super::loader::parse_module;
use super::value::{ConstValue, eval_const};
use crate::codec::b85_decode;
use crate::error::{Error, Result};

mod emit;
mod lift;

use emit::render_string_literal;
use lift::{lift_function, render_indented};

pub(crate) const ASSETS_NAME: &str = "__pw_ab_assets__";
pub(crate) const DISPATCH_NAME: &str = "__pw_ab_dispatch__";
const EXEC_NAME: &str = "__pw_ab_exec__";

const PACKET_LAYOUTS: [[usize; 3]; 6] = [
    [0, 1, 2],
    [0, 2, 1],
    [1, 0, 2],
    [1, 2, 0],
    [2, 0, 1],
    [2, 1, 0],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Op {
    Const,
    Load,
    Store,
    Pop,
    Dup,
    Bin,
    Unary,
    CompareChain,
    Jump,
    JumpIfFalse,
    JumpIfTrueKeep,
    JumpIfFalseKeep,
    Call,
    GetAttr,
    Subscr,
    BuildSlice,
    BuildList,
    BuildTuple,
    BuildSet,
    BuildDict,
    Return,
    GetIter,
    ForIter,
    Unpack,
    BuildString,
    FormatValue,
}

#[derive(Debug, Clone)]
enum Const {
    None,
    Ellipsis,
    Bool(bool),
    Int(String),
    Float(String),
    Str(String),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone)]
struct Instruction {
    op: Op,
    args: Vec<Json>,
}

#[derive(Debug, Clone)]
struct AbyssFunction {
    entry: usize,
    consts: Vec<Const>,
    globals: BTreeSet<String>,
}

#[derive(Debug)]
struct AbyssDoc {
    code: Vec<Instruction>,
    funcs: Vec<AbyssFunction>,
}

#[derive(Debug)]
pub(crate) struct DevirtReport {
    pub(crate) lifted: usize,
    pub(crate) refused: usize,
}

pub(crate) fn has_abyss(module: &ModModule) -> bool {
    let mut has_assets: bool = false;
    let mut has_dispatch: bool = false;
    for stmt in &module.body {
        match stmt {
            Stmt::Assign(StmtAssign { targets, .. }) => {
                if let [Expr::Name(name)] = targets.as_slice()
                    && name.id.as_str() == ASSETS_NAME
                {
                    has_assets = true;
                }
            }
            Stmt::FunctionDef(func) if func.name.as_str() == DISPATCH_NAME => {
                has_dispatch = true;
            }
            _ => {}
        }
    }
    has_assets && has_dispatch
}

pub(crate) fn devirtualize(source: &str) -> Result<(String, DevirtReport)> {
    let module: ModModule = parse_module(source)?;
    if !has_abyss(&module) {
        return Ok((
            source.to_owned(),
            DevirtReport {
                lifted: 0,
                refused: 0,
            },
        ));
    }
    let assets: (Vec<u8>, Vec<u8>) = locate_assets(&module)
        .ok_or_else(|| Error::AstCleanup("abyss assets tuple not found".to_owned()))?;
    let opcode_map: BTreeMap<i64, Op> = locate_opcode_map(&module)
        .ok_or_else(|| Error::AstCleanup("abyss opcode dispatch not recoverable".to_owned()))?;
    let doc: AbyssDoc = decode_doc(&assets.0, &assets.1, &opcode_map)?;

    let mut lifted_bodies: BTreeMap<usize, String> = BTreeMap::new();
    let mut report: DevirtReport = DevirtReport {
        lifted: 0,
        refused: 0,
    };
    for stmt in &module.body {
        let Some((fid, indent)): Option<(usize, usize)> = wrapper_target(stmt) else {
            continue;
        };
        let Some(func): Option<&AbyssFunction> = doc.funcs.get(fid) else {
            continue;
        };
        match lift_function(&doc, func) {
            Ok(body) => {
                lifted_bodies.insert(fid, render_indented(&body, indent));
                report.lifted += 1;
            }
            Err(_) => report.refused += 1,
        }
    }
    walk_methods(&module, &doc, &mut lifted_bodies, &mut report);

    if lifted_bodies.is_empty() {
        return Ok((source.to_owned(), report));
    }
    let rebuilt: String = rebuild_source(source, &module, &lifted_bodies)?;
    Ok((rebuilt, report))
}

fn walk_methods(
    module: &ModModule,
    doc: &AbyssDoc,
    lifted: &mut BTreeMap<usize, String>,
    report: &mut DevirtReport,
) {
    for stmt in &module.body {
        let Stmt::ClassDef(class): &Stmt = stmt else {
            continue;
        };
        for member in &class.body {
            let Some((fid, indent)): Option<(usize, usize)> = wrapper_target(member) else {
                continue;
            };
            if lifted.contains_key(&fid) {
                continue;
            }
            let Some(func): Option<&AbyssFunction> = doc.funcs.get(fid) else {
                continue;
            };
            match lift_function(doc, func) {
                Ok(body) => {
                    lifted.insert(fid, render_indented(&body, indent));
                    report.lifted += 1;
                }
                Err(_) => report.refused += 1,
            }
        }
    }
}

fn locate_assets(module: &ModModule) -> Option<(Vec<u8>, Vec<u8>)> {
    for stmt in &module.body {
        let Stmt::Assign(StmtAssign { targets, value, .. }): &Stmt = stmt else {
            continue;
        };
        let [Expr::Name(name)]: &[Expr] = targets.as_slice() else {
            continue;
        };
        if name.id.as_str() != ASSETS_NAME {
            continue;
        }
        let ConstValue::Tuple(pair): ConstValue = eval_const(value)? else {
            return None;
        };
        let [ConstValue::Bytes(payload), ConstValue::Bytes(key)]: &[ConstValue] = pair.as_slice()
        else {
            return None;
        };
        let payload_raw: Vec<u8> = b85_decode(payload).ok()?;
        let key_raw: Vec<u8> = b85_decode(key).ok()?;
        return Some((payload_raw, key_raw));
    }
    None
}

fn locate_opcode_map(module: &ModModule) -> Option<BTreeMap<i64, Op>> {
    let exec: &StmtFunctionDef = module.body.iter().find_map(|stmt: &Stmt| match stmt {
        Stmt::FunctionDef(func) if func.name.as_str() == EXEC_NAME => Some(func),
        _ => None,
    })?;
    let loop_body: &[Stmt] = exec.body.iter().find_map(|stmt: &Stmt| match stmt {
        Stmt::While(w) => Some(w.body.as_slice()),
        _ => None,
    })?;
    let mut map: BTreeMap<i64, Op> = BTreeMap::new();
    for stmt in loop_body {
        collect_dispatch_arms(stmt, &mut map);
    }
    if map.len() < 26 {
        return None;
    }
    Some(map)
}

fn collect_dispatch_arms(stmt: &Stmt, map: &mut BTreeMap<i64, Op>) {
    let Stmt::If(branch): &Stmt = stmt else {
        return;
    };
    if let Some((byte, op)) = match_dispatch_test(&branch.test, &branch.body) {
        map.entry(byte).or_insert(op);
    }
    for clause in &branch.elif_else_clauses {
        if let Some(test) = clause.test.as_ref()
            && let Some((byte, op)) = match_dispatch_test(test, &clause.body)
        {
            map.entry(byte).or_insert(op);
        }
    }
}

fn match_dispatch_test(test: &Expr, body: &[Stmt]) -> Option<(i64, Op)> {
    let Expr::Compare(compare): &Expr = test else {
        return None;
    };
    let Expr::Name(ExprName { id, .. }): &Expr = compare.left.as_ref() else {
        return None;
    };
    if id.as_str() != "_op" {
        return None;
    }
    let ConstValue::Int(byte): ConstValue = eval_const(compare.comparators.first()?)? else {
        return None;
    };
    let text: String = block_text(body);
    let op: Op = classify_block(&text)?;
    Some((byte, op))
}

fn block_text(body: &[Stmt]) -> String {
    let mut out: String = String::new();
    for stmt in body {
        out.push_str(&debug_stmt(stmt));
        out.push('\n');
    }
    out
}

fn debug_stmt(stmt: &Stmt) -> String {
    format!("{stmt:?}")
}

fn classify_block(text: &str) -> Option<Op> {
    let op: Op = if text.contains("__pw_ab_get__") {
        Op::Load
    } else if text.contains("__pw_ab_store__") {
        Op::Store
    } else if text.contains("__pw_ab_bin__") {
        Op::Bin
    } else if text.contains("__pw_ab_unary__") {
        Op::Unary
    } else if text.contains("__pw_ab_compare__") {
        Op::CompareChain
    } else if text.contains("__pw_ab_format__") {
        Op::FormatValue
    } else if contains_call(text, "getattr") {
        Op::GetAttr
    } else if contains_call(text, "slice") {
        Op::BuildSlice
    } else if contains_call(text, "iter") {
        Op::GetIter
    } else if contains_call(text, "next") {
        Op::ForIter
    } else if text.contains("_consts") {
        Op::Const
    } else if contains_call(text, "tuple") {
        Op::BuildTuple
    } else if contains_call(text, "set") {
        Op::BuildSet
    } else if contains_call(text, "dict") {
        Op::BuildDict
    } else if text.contains("\"join\"") {
        Op::BuildString
    } else if text.contains("_func") {
        Op::Call
    } else if text.contains("unpack") {
        Op::Unpack
    } else if text.contains("_obj") {
        Op::Subscr
    } else if text.contains("Return") {
        Op::Return
    } else {
        return classify_jump_block(text);
    };
    Some(op)
}

fn contains_call(text: &str, name: &str) -> bool {
    text.contains(&format!("Name(\"{name}\")"))
}

fn classify_jump_block(text: &str) -> Option<Op> {
    let has_if: bool = text.contains("StmtIf");
    let has_not: bool = text.contains("UnaryOp") && text.contains("Not");
    let has_ternary: bool = text.contains("ExprIf");
    let pops: usize = text.matches("\"pop\"").count();
    let appends_subscript: bool =
        text.contains("\"append\"") && text.contains("Subscript") && text.contains("Number");
    if has_if {
        if has_not {
            return Some(Op::JumpIfFalseKeep);
        }
        return Some(Op::JumpIfTrueKeep);
    }
    if has_ternary {
        return Some(Op::JumpIfFalse);
    }
    if appends_subscript && pops == 0 {
        return Some(Op::Dup);
    }
    if text.contains("_items") {
        return Some(Op::BuildList);
    }
    if pops == 1 && !text.contains("append") {
        return Some(Op::Pop);
    }
    if !text.contains("append") && !text.contains("pop") {
        return Some(Op::Jump);
    }
    None
}

fn xor_payload(payload: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return payload.to_vec();
    }
    payload
        .iter()
        .enumerate()
        .map(|(i, &b): (usize, &u8)| b ^ key[i % key.len()])
        .collect()
}

fn unseal(field: &Json, salt: i64) -> Option<Json> {
    let parts: &Vec<Json> = field.as_array()?;
    let [share, other, key, add, step]: &[Json] = parts.as_slice() else {
        return None;
    };
    let share: Vec<u8> = b85_decode(share.as_str()?.as_bytes()).ok()?;
    let other: Vec<u8> = b85_decode(other.as_str()?.as_bytes()).ok()?;
    let key: Vec<u8> = b85_decode(key.as_str()?.as_bytes()).ok()?;
    let add: i64 = add.as_i64()?;
    let step: i64 = step.as_i64()?;
    if key.is_empty() || share.len() != other.len() {
        return None;
    }
    let encoded: Vec<u8> = share
        .iter()
        .zip(other.iter())
        .map(|(&a, &b): (&u8, &u8)| a ^ b)
        .collect();
    let mut raw: Vec<u8> = Vec::with_capacity(encoded.len());
    for (i, &b) in encoded.iter().enumerate() {
        let idx: i64 = i64::try_from(i).ok()?;
        let shifted: i64 = (i64::from(b) - add - (idx + salt) * step).rem_euclid(256);
        let byte: u8 = u8::try_from(shifted).ok()? ^ key[i % key.len()];
        raw.push(byte);
    }
    serde_json::from_slice(&raw).ok()
}

fn decode_doc(payload: &[u8], key: &[u8], opcode_map: &BTreeMap<i64, Op>) -> Result<AbyssDoc> {
    let plaintext: Vec<u8> = xor_payload(payload, key);
    let doc: Json = serde_json::from_slice(&plaintext)
        .map_err(|e| Error::AstCleanup(format!("abyss doc json invalid: {e}")))?;
    let salt: i64 = doc
        .get("m")
        .and_then(|m: &Json| m.get("s"))
        .and_then(Json::as_i64)
        .ok_or_else(|| Error::AstCleanup("abyss doc missing salt".to_owned()))?;
    let packets: &Vec<Json> = doc
        .get("p")
        .and_then(Json::as_array)
        .ok_or_else(|| Error::AstCleanup("abyss doc missing packet stream".to_owned()))?;
    let funcs_json: &Vec<Json> = doc
        .get("f")
        .and_then(Json::as_array)
        .ok_or_else(|| Error::AstCleanup("abyss doc missing function table".to_owned()))?;

    let mut code: Vec<Instruction> = Vec::with_capacity(packets.len());
    for (index, packet) in packets.iter().enumerate() {
        let inst: Instruction = decode_packet(packet, index, salt, opcode_map)
            .ok_or_else(|| Error::AstCleanup(format!("abyss packet {index} did not decode")))?;
        code.push(inst);
    }

    let mut funcs: Vec<AbyssFunction> = Vec::with_capacity(funcs_json.len());
    for (fi, fn_json) in funcs_json.iter().enumerate() {
        let fi64: i64 = i64::try_from(fi)
            .map_err(|_| Error::AstCleanup("abyss function index overflow".to_owned()))?;
        let entry_json: &Json = fn_json
            .get("e")
            .ok_or_else(|| Error::AstCleanup("abyss function missing entry".to_owned()))?;
        let entry_val: Json = unseal(entry_json, salt + 200_000 + fi64)
            .ok_or_else(|| Error::AstCleanup("abyss entry unseal failed".to_owned()))?;
        let entry: usize = usize::try_from(
            entry_val
                .as_i64()
                .ok_or_else(|| Error::AstCleanup("abyss entry not int".to_owned()))?,
        )
        .map_err(|_| Error::AstCleanup("abyss entry negative".to_owned()))?;

        let globals_json: &Json = fn_json
            .get("g")
            .ok_or_else(|| Error::AstCleanup("abyss function missing globals".to_owned()))?;
        let globals_val: Json = unseal(globals_json, salt + 300_000 + fi64)
            .ok_or_else(|| Error::AstCleanup("abyss globals unseal failed".to_owned()))?;
        let globals: BTreeSet<String> = globals_val
            .as_array()
            .map(|arr: &Vec<Json>| {
                arr.iter()
                    .filter_map(|v: &Json| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        let consts_json: &Vec<Json> = fn_json
            .get("c")
            .and_then(Json::as_array)
            .ok_or_else(|| Error::AstCleanup("abyss function missing consts".to_owned()))?;
        let mut consts: Vec<Const> = Vec::with_capacity(consts_json.len());
        for (ci, item) in consts_json.iter().enumerate() {
            let ci64: i64 = i64::try_from(ci)
                .map_err(|_| Error::AstCleanup("abyss const index overflow".to_owned()))?;
            let salt_c: i64 = salt + (fi64 + 1) * 100_000 + ci64;
            let encoded: Json = unseal(item, salt_c)
                .ok_or_else(|| Error::AstCleanup("abyss const unseal failed".to_owned()))?;
            consts.push(decode_const(&encoded)?);
        }

        funcs.push(AbyssFunction {
            entry,
            consts,
            globals,
        });
    }

    Ok(AbyssDoc { code, funcs })
}

fn decode_packet(
    packet: &Json,
    index: usize,
    salt: i64,
    opcode_map: &BTreeMap<i64, Op>,
) -> Option<Instruction> {
    let arr: &Vec<Json> = packet.as_array()?;
    let layout_id: usize = usize::try_from(arr.first()?.as_i64()?).ok()?;
    let layout: &[usize; 3] = PACKET_LAYOUTS.get(layout_id % PACKET_LAYOUTS.len())?;
    let mut fields: [Option<&Json>; 3] = [None, None, None];
    for (pos, &slot) in layout.iter().enumerate() {
        fields[slot] = arr.get(pos + 1);
    }
    let index64: i64 = i64::try_from(index).ok()?;
    let op_val: Json = unseal(fields[0]?, salt + index64 * 5 + 1)?;
    let args_val: Json = unseal(fields[1]?, salt + index64 * 5 + 2)?;
    let op_byte: i64 = op_val.as_i64()?;
    let op: Op = *opcode_map.get(&op_byte)?;
    let args: Vec<Json> = args_val.as_array()?.clone();
    Some(Instruction { op, args })
}

fn decode_const(encoded: &Json) -> Result<Const> {
    let t: &str = encoded
        .get("t")
        .and_then(Json::as_str)
        .ok_or_else(|| Error::AstCleanup("abyss const missing tag".to_owned()))?;
    let value: Const = match t {
        "none" => Const::None,
        "ellipsis" => Const::Ellipsis,
        "bool" => Const::Bool(
            encoded
                .get("v")
                .and_then(Json::as_bool)
                .ok_or_else(|| Error::AstCleanup("abyss bool const".to_owned()))?,
        ),
        "int" => Const::Int(
            encoded
                .get("v")
                .and_then(Json::as_str)
                .ok_or_else(|| Error::AstCleanup("abyss int const".to_owned()))?
                .to_owned(),
        ),
        "float" => Const::Float(
            encoded
                .get("v")
                .and_then(Json::as_str)
                .ok_or_else(|| Error::AstCleanup("abyss float const".to_owned()))?
                .to_owned(),
        ),
        "str" => Const::Str(
            encoded
                .get("v")
                .and_then(Json::as_str)
                .ok_or_else(|| Error::AstCleanup("abyss str const".to_owned()))?
                .to_owned(),
        ),
        "bytes" => {
            let b85: &str = encoded
                .get("v")
                .and_then(Json::as_str)
                .ok_or_else(|| Error::AstCleanup("abyss bytes const".to_owned()))?;
            Const::Bytes(b85_decode(b85.as_bytes())?)
        }
        other => {
            return Err(Error::AstCleanup(format!(
                "abyss unknown const tag {other}"
            )));
        }
    };
    Ok(value)
}

fn wrapper_target(stmt: &Stmt) -> Option<(usize, usize)> {
    let Stmt::FunctionDef(func): &Stmt = stmt else {
        return None;
    };
    let ret: &StmtReturn = func.body.iter().rev().find_map(|s: &Stmt| match s {
        Stmt::Return(r) => Some(r),
        _ => None,
    })?;
    let Expr::Call(ExprCall {
        func: call_func,
        arguments,
        ..
    }): &Expr = ret.value.as_deref()?
    else {
        return None;
    };
    let Expr::Name(ExprName { id, .. }): &Expr = call_func.as_ref() else {
        return None;
    };
    if id.as_str() != DISPATCH_NAME {
        return None;
    }
    let ConstValue::Int(fid): ConstValue = eval_const(arguments.args.first()?)? else {
        return None;
    };
    let fid: usize = usize::try_from(fid).ok()?;
    Some((fid, 1))
}

fn rebuild_source(
    source: &str,
    module: &ModModule,
    lifted: &BTreeMap<usize, String>,
) -> Result<String> {
    let mut wrappers: BTreeMap<String, usize> = BTreeMap::new();
    collect_wrapper_names(&module.body, &mut wrappers);

    let mut out: String = String::with_capacity(source.len());
    for stmt in &module.body {
        if is_dropped_helper(stmt) {
            continue;
        }
        emit_stmt(stmt, source, &wrappers, lifted, 0, &mut out)?;
    }
    Ok(out)
}

fn collect_wrapper_names(body: &[Stmt], wrappers: &mut BTreeMap<String, usize>) {
    for stmt in body {
        if let Some((fid, _indent)) = wrapper_target(stmt)
            && let Stmt::FunctionDef(func) = stmt
        {
            wrappers.insert(func.name.to_string(), fid);
        }
        if let Stmt::ClassDef(class) = stmt {
            collect_wrapper_names(&class.body, wrappers);
        }
    }
}

fn is_dropped_helper(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Assign(StmtAssign { targets, .. }) => {
            matches!(targets.as_slice(), [Expr::Name(name)] if name.id.as_str() == ASSETS_NAME
                || name.id.as_str() == "__pw_ab_cache__")
        }
        Stmt::FunctionDef(func) => func.name.as_str().starts_with("__pw_ab_"),
        Stmt::Global(g) => g.names.iter().any(|n| n.as_str() == "__pw_ab_cache__"),
        _ => false,
    }
}

fn emit_stmt(
    stmt: &Stmt,
    source: &str,
    wrappers: &BTreeMap<String, usize>,
    lifted: &BTreeMap<usize, String>,
    indent: usize,
    out: &mut String,
) -> Result<()> {
    if let Stmt::FunctionDef(func) = stmt
        && let Some(&fid) = wrappers.get(func.name.as_str())
        && let Some(body) = lifted.get(&fid)
    {
        emit_function_header(func, indent, out);
        out.push_str(body);
        return Ok(());
    }
    if let Stmt::ClassDef(class) = stmt {
        emit_class_header(class, indent, out);
        let mut emitted_any: bool = false;
        for member in &class.body {
            if is_dropped_helper(member) {
                continue;
            }
            emit_stmt(member, source, wrappers, lifted, indent + 1, out)?;
            emitted_any = true;
        }
        if !emitted_any {
            let pad: String = "    ".repeat(indent + 1);
            out.push_str(&pad);
            out.push_str("pass\n");
        }
        return Ok(());
    }
    let rendered: String = render_with_generator(source, stmt)?;
    for line in rendered.lines() {
        if line.is_empty() {
            out.push('\n');
            continue;
        }
        let pad: String = "    ".repeat(indent);
        out.push_str(&pad);
        out.push_str(line);
        out.push('\n');
    }
    Ok(())
}

fn emit_function_header(func: &StmtFunctionDef, indent: usize, out: &mut String) {
    let pad: String = "    ".repeat(indent);
    for decorator in &func.decorator_list {
        out.push_str(&pad);
        out.push('@');
        out.push_str(&simple_expr_text(&decorator.expression));
        out.push('\n');
    }
    out.push_str(&pad);
    out.push_str("def ");
    out.push_str(func.name.as_str());
    out.push('(');
    out.push_str(&render_parameters(func));
    out.push_str("):\n");
}

fn emit_class_header(class: &ruff_python_ast::StmtClassDef, indent: usize, out: &mut String) {
    let pad: String = "    ".repeat(indent);
    out.push_str(&pad);
    out.push_str("class ");
    out.push_str(class.name.as_str());
    if let Some(arguments) = class.arguments.as_ref() {
        let mut parts: Vec<String> = Vec::new();
        for arg in &arguments.args {
            parts.push(simple_expr_text(arg));
        }
        for kw in &arguments.keywords {
            if let Some(name) = kw.arg.as_ref() {
                parts.push(format!("{}={}", name, simple_expr_text(&kw.value)));
            }
        }
        if !parts.is_empty() {
            out.push('(');
            out.push_str(&parts.join(", "));
            out.push(')');
        }
    }
    out.push_str(":\n");
}

fn render_parameters(func: &StmtFunctionDef) -> String {
    let params: &ruff_python_ast::Parameters = &func.parameters;
    let mut parts: Vec<String> = Vec::new();
    for arg in &params.posonlyargs {
        parts.push(parameter_text(arg));
    }
    if !params.posonlyargs.is_empty() {
        parts.push("/".to_owned());
    }
    for arg in &params.args {
        parts.push(parameter_text(arg));
    }
    if let Some(vararg) = params.vararg.as_ref() {
        parts.push(format!("*{}", vararg.name));
    } else if !params.kwonlyargs.is_empty() {
        parts.push("*".to_owned());
    }
    for arg in &params.kwonlyargs {
        parts.push(parameter_text(arg));
    }
    if let Some(kwarg) = params.kwarg.as_ref() {
        parts.push(format!("**{}", kwarg.name));
    }
    parts.join(", ")
}

fn parameter_text(arg: &ruff_python_ast::ParameterWithDefault) -> String {
    let name: &str = arg.parameter.name.as_str();
    arg.default.as_deref().map_or_else(
        || name.to_owned(),
        |default: &Expr| format!("{name}={}", simple_expr_text(default)),
    )
}

fn simple_expr_text(expr: &Expr) -> String {
    match expr {
        Expr::Name(ExprName { id, .. }) => id.to_string(),
        Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
            render_string_literal(value.to_str())
        }
        Expr::Attribute(attr) => {
            format!("{}.{}", simple_expr_text(&attr.value), attr.attr)
        }
        Expr::Call(call) => {
            let mut parts: Vec<String> = call.arguments.args.iter().map(simple_expr_text).collect();
            for kw in &call.arguments.keywords {
                if let Some(name) = kw.arg.as_ref() {
                    parts.push(format!("{}={}", name, simple_expr_text(&kw.value)));
                }
            }
            format!("{}({})", simple_expr_text(&call.func), parts.join(", "))
        }
        _ => render_const_expr(expr),
    }
}

fn render_const_expr(expr: &Expr) -> String {
    match eval_const(expr) {
        Some(ConstValue::Int(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn render_with_generator(source: &str, stmt: &Stmt) -> Result<String> {
    use ruff_python_codegen::{Generator, Stylist};
    use ruff_python_parser::{Mode, ParseOptions, parse};
    let parsed: ruff_python_parser::Parsed<ruff_python_ast::Mod> =
        parse(source, ParseOptions::from(Mode::Module))
            .map_err(|e| Error::AstCleanup(format!("rebuild parse failed: {e}")))?;
    let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), source);
    Ok(Generator::from(&stylist).stmt(stmt))
}
