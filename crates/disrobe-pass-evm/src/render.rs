use crate::expr::{BinOp, CdLoc, Env, Expr, TernOp, UnOp, Val, as_const};
use crate::proxy::slot_name;
use crate::u256::U256;

const MAX_RENDER: usize = 600;

pub(crate) fn constant(value: U256) -> String {
    match value.to_u64() {
        Some(small) if small < 1024 => small.to_string(),
        _ => value.to_string(),
    }
}

const fn env(kind: Env) -> &'static str {
    match kind {
        Env::Address => "address(this)",
        Env::Origin => "tx.origin",
        Env::Caller => "msg.sender",
        Env::CallValue => "msg.value",
        Env::GasPrice => "tx.gasprice",
        Env::Coinbase => "block.coinbase",
        Env::Timestamp => "block.timestamp",
        Env::Number => "block.number",
        Env::PrevRandao => "block.prevrandao",
        Env::GasLimit => "block.gaslimit",
        Env::ChainId => "block.chainid",
        Env::SelfBalance => "address(this).balance",
        Env::BaseFee => "block.basefee",
        Env::BlobBaseFee => "block.blobbasefee",
        Env::CodeSize => "codesize()",
        Env::ReturnDataSize => "returndatasize()",
        Env::Gas => "gasleft()",
        Env::MemorySize => "msize()",
    }
}

fn is_atom(value: &Val) -> bool {
    !matches!(value.expr, Expr::Bin(..) | Expr::Tern(..))
        || matches!(value.expr, Expr::Bin(BinOp::And, _, ref mask) if cast_name(mask).is_some())
}

fn operand(value: &Val) -> String {
    let text: String = expr(value);
    if is_atom(value) {
        text
    } else {
        format!("({text})")
    }
}

fn cast_name(mask: &Val) -> Option<String> {
    let mask: U256 = as_const(mask)?;
    if let Some(bits) = mask
        .low_mask_bits()
        .filter(|bits: &u32| bits.is_multiple_of(8) && *bits < 256)
    {
        return Some(if bits == 160 {
            "address".to_owned()
        } else {
            format!("uint{bits}")
        });
    }
    mask.high_mask_bits()
        .filter(|bits: &u32| bits.is_multiple_of(8) && *bits < 256)
        .map(|bits: u32| format!("bytes{}", bits / 8))
}

pub(crate) fn is_boolean(value: &Val) -> bool {
    matches!(
        value.expr,
        Expr::Un(UnOp::IsZero, _)
            | Expr::Bin(
                BinOp::Lt | BinOp::Gt | BinOp::Slt | BinOp::Sgt | BinOp::Eq,
                _,
                _
            )
    )
}

pub(crate) fn slot(value: &Val) -> String {
    if let Some(constant) = as_const(value) {
        if let Some(name) = slot_name(constant) {
            return format!("storage[{name}]");
        }
        return format!("storage[{}]", self::constant(constant));
    }
    if let Some(text) = mapping(value) {
        return text;
    }
    format!("storage[{}]", expr(value))
}

fn mapping(value: &Val) -> Option<String> {
    let Expr::Keccak(words) = &value.expr else {
        return None;
    };
    let [key, base] = words.as_slice() else {
        return None;
    };
    let prefix: String = match as_const(base) {
        Some(index) => format!("mapping_{}", constant(index)),
        None => mapping(base)?,
    };
    Some(format!("{prefix}[{}]", expr(key)))
}

pub(crate) fn expr(value: &Val) -> String {
    let mut text: String = render(value);
    if text.len() > MAX_RENDER {
        let mut cut: usize = MAX_RENDER;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str("...");
    }
    text
}

fn render(value: &Val) -> String {
    match &value.expr {
        Expr::Const(constant) => self::constant(*constant),
        Expr::Cd(CdLoc::Word0) => "msg.data[0:32]".to_owned(),
        Expr::Cd(CdLoc::Head(index)) => format!("arg{index}"),
        Expr::Cd(CdLoc::Length(index)) => format!("arg{index}.length"),
        Expr::Cd(CdLoc::Element(index)) => format!("arg{index}[i]"),
        Expr::Cd(CdLoc::Nested(index)) => format!("arg{index}[i][j]"),
        Expr::CdRaw(offset) => format!("calldataload({})", expr(offset)),
        Expr::CdSize => "msg.data.length".to_owned(),
        Expr::Env(kind) => env(*kind).to_owned(),
        Expr::Un(op, a) => match op {
            UnOp::IsZero => match &a.expr {
                Expr::Un(UnOp::IsZero, inner) => format!("bool({})", expr(inner)),
                Expr::Bin(BinOp::Eq, x, y) => format!("{} != {}", operand(x), operand(y)),
                Expr::Bin(BinOp::Lt, x, y) => format!("{} >= {}", operand(x), operand(y)),
                Expr::Bin(BinOp::Gt, x, y) => format!("{} <= {}", operand(x), operand(y)),
                _ if is_boolean(a) => format!("!({})", expr(a)),
                _ => format!("{} == 0", operand(a)),
            },
            UnOp::Not => format!("~{}", operand(a)),
            UnOp::Balance => format!("{}.balance", operand(a)),
            UnOp::ExtCodeSize => format!("{}.code.length", operand(a)),
            UnOp::ExtCodeHash => format!("{}.codehash", operand(a)),
            UnOp::BlockHash => format!("blockhash({})", expr(a)),
            UnOp::BlobHash => format!("blobhash({})", expr(a)),
            UnOp::Clz => format!("clz({})", expr(a)),
        },
        Expr::Bin(op, a, b) => binary(*op, a, b),
        Expr::Tern(op, a, b, c) => {
            let name: &str = match op {
                TernOp::AddMod => "addmod",
                TernOp::MulMod => "mulmod",
            };
            format!("{name}({}, {}, {})", expr(a), expr(b), expr(c))
        }
        Expr::Sload(index) => slot(index),
        Expr::Tload(index) => format!("transient[{}]", expr(index)),
        Expr::Keccak(words) => {
            if let Some(text) = mapping(value) {
                return format!("slot({text})");
            }
            let parts: Vec<String> = words.iter().map(expr).collect();
            format!("keccak256(abi.encode({}))", parts.join(", "))
        }
        Expr::CallResult(pc) => format!("success_{pc:x}"),
        Expr::Created(pc) => format!("created_{pc:x}"),
        Expr::Opaque(pc) => format!("tmp_{pc:x}"),
    }
}

fn binary(op: BinOp, a: &Val, b: &Val) -> String {
    let infix = |symbol: &str| format!("{} {symbol} {}", operand(a), operand(b));
    match op {
        BinOp::Add => match as_const(b).filter(|c: &U256| c.is_negative()) {
            Some(negative) => format!("{} - {}", operand(a), constant(negative.wrapping_neg())),
            None => infix("+"),
        },
        BinOp::Sub => infix("-"),
        BinOp::Mul => infix("*"),
        BinOp::Div => infix("/"),
        BinOp::Mod => infix("%"),
        BinOp::Exp => infix("**"),
        BinOp::Lt => infix("<"),
        BinOp::Gt => infix(">"),
        BinOp::Eq => infix("=="),
        BinOp::Or => infix("|"),
        BinOp::Xor => infix("^"),
        BinOp::SDiv => format!("sdiv({}, {})", expr(a), expr(b)),
        BinOp::SMod => format!("smod({}, {})", expr(a), expr(b)),
        BinOp::Slt => format!("slt({}, {})", expr(a), expr(b)),
        BinOp::Sgt => format!("sgt({}, {})", expr(a), expr(b)),
        BinOp::Byte => format!("byte({}, {})", expr(a), expr(b)),
        BinOp::SignExtend => match as_const(a).and_then(U256::to_u64) {
            Some(index) if index < 31 => format!("int{}({})", (index + 1) * 8, expr(b)),
            _ => format!("signextend({}, {})", expr(a), expr(b)),
        },
        BinOp::And => match cast_name(b) {
            Some(name) => format!("{name}({})", expr(a)),
            None => infix("&"),
        },
        BinOp::Shl => format!("{} << {}", operand(b), operand(a)),
        BinOp::Shr => format!("{} >> {}", operand(b), operand(a)),
        BinOp::Sar => format!("sar({}, {})", expr(b), expr(a)),
    }
}
