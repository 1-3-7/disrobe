use ruff_python_ast::{
    Expr, ExprAttribute, ExprBytesLiteral, ExprCall, ExprName, ExprNumberLiteral,
    ExprStringLiteral, ExprSubscript, ExprTuple, Number,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConstValue {
    Bytes(Vec<u8>),
    Int(i64),
    Tuple(Vec<Self>),
}

pub(crate) fn eval_const(expr: &Expr) -> Option<ConstValue> {
    match expr {
        Expr::BytesLiteral(ExprBytesLiteral { value, .. }) => Some(ConstValue::Bytes(
            value.iter().flat_map(|b| b.value.iter().copied()).collect(),
        )),
        Expr::NumberLiteral(ExprNumberLiteral {
            value: Number::Int(int),
            ..
        }) => int.as_i64().map(ConstValue::Int),
        Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
            Some(ConstValue::Bytes(value.to_str().as_bytes().to_vec()))
        }
        Expr::Tuple(ExprTuple { elts, .. }) => {
            let mut out: Vec<ConstValue> = Vec::with_capacity(elts.len());
            for elt in elts {
                out.push(eval_const(elt)?);
            }
            Some(ConstValue::Tuple(out))
        }
        Expr::List(list) => {
            let mut out: Vec<ConstValue> = Vec::with_capacity(list.elts.len());
            for elt in &list.elts {
                out.push(eval_const(elt)?);
            }
            Some(ConstValue::Tuple(out))
        }
        Expr::Call(call) => eval_call(call),
        Expr::Subscript(sub) => eval_subscript(sub),
        Expr::UnaryOp(u) => {
            let operand: ConstValue = eval_const(&u.operand)?;
            match (u.op, operand) {
                (ruff_python_ast::UnaryOp::USub, ConstValue::Int(n)) => {
                    Some(ConstValue::Int(n.checked_neg()?))
                }
                (ruff_python_ast::UnaryOp::UAdd, ConstValue::Int(n)) => Some(ConstValue::Int(n)),
                _ => None,
            }
        }
        _ => None,
    }
}

fn eval_call(call: &ExprCall) -> Option<ConstValue> {
    if let Expr::Attribute(ExprAttribute { value, attr, .. }) = call.func.as_ref() {
        let attr_name: &str = attr.as_str();
        if attr_name == "fromhex"
            && let Expr::Name(ExprName { id, .. }) = value.as_ref()
            && id.as_str() == "bytes"
            && let Some(ConstValue::Bytes(hex_bytes)) =
                call.arguments.args.first().and_then(eval_const)
        {
            let hex_str: String = String::from_utf8(hex_bytes).ok()?;
            let cleaned: String = hex_str.chars().filter(|c| !c.is_whitespace()).collect();
            if !cleaned.len().is_multiple_of(2) {
                return None;
            }
            let decoded: Vec<u8> = (0..cleaned.len())
                .step_by(2)
                .map(|i: usize| u8::from_str_radix(cleaned.get(i..i + 2)?, 16).ok())
                .collect::<Option<Vec<u8>>>()?;
            return Some(ConstValue::Bytes(decoded));
        }
        if attr_name == "join"
            && let Some(ConstValue::Bytes(sep)) = eval_const(value)
            && sep.is_empty()
        {
            return eval_join_argument(call.arguments.args.first()?);
        }
    }
    None
}

fn eval_join_argument(arg: &Expr) -> Option<ConstValue> {
    match arg {
        Expr::Generator(generator) => {
            eval_chunk_generator(&generator.elt, generator.generators.as_slice())
        }
        Expr::Tuple(ExprTuple { elts, .. })
        | Expr::List(ruff_python_ast::ExprList { elts, .. }) => {
            let mut joined: Vec<u8> = Vec::new();
            for elt in elts {
                let ConstValue::Bytes(part): ConstValue = eval_const(elt)? else {
                    return None;
                };
                joined.extend_from_slice(&part);
            }
            Some(ConstValue::Bytes(joined))
        }
        _ => None,
    }
}

fn eval_chunk_generator(
    element: &Expr,
    comprehensions: &[ruff_python_ast::Comprehension],
) -> Option<ConstValue> {
    let [comprehension]: &[ruff_python_ast::Comprehension] = comprehensions else {
        return None;
    };
    if !comprehension.ifs.is_empty() {
        return None;
    }
    let Expr::Name(loop_var): &Expr = &comprehension.target else {
        return None;
    };
    let ConstValue::Tuple(indices): ConstValue = eval_const(&comprehension.iter)? else {
        return None;
    };
    let Expr::Subscript(ExprSubscript { value, slice, .. }): &Expr = element else {
        return None;
    };
    let Expr::Name(index_name): &Expr = slice.as_ref() else {
        return None;
    };
    if index_name.id.as_str() != loop_var.id.as_str() {
        return None;
    }
    let ConstValue::Tuple(chunks): ConstValue = eval_const(value)? else {
        return None;
    };
    let mut joined: Vec<u8> = Vec::new();
    for index in indices {
        let ConstValue::Int(i): ConstValue = index else {
            return None;
        };
        let pos: usize = usize::try_from(i).ok()?;
        let ConstValue::Bytes(part): &ConstValue = chunks.get(pos)? else {
            return None;
        };
        joined.extend_from_slice(part);
    }
    Some(ConstValue::Bytes(joined))
}

fn eval_subscript(sub: &ExprSubscript) -> Option<ConstValue> {
    let ConstValue::Tuple(items): ConstValue = eval_const(&sub.value)? else {
        return None;
    };
    let ConstValue::Int(i): ConstValue = eval_const(&sub.slice)? else {
        return None;
    };
    let pos: usize = usize::try_from(i).ok()?;
    items.get(pos).cloned()
}
