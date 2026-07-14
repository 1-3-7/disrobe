use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use disrobe_sleigh::decode_block;
use disrobe_sleigh::pcode::{DecodeStatus, PcodeInstr, PcodeOp, Space, Varnode};

#[derive(Clone, Debug, Eq, PartialEq)]
enum Expression {
    Binary {
        name: &'static str,
        left: Box<Self>,
        right: Box<Self>,
    },
    Load {
        pointer: Box<Self>,
        size_bytes: u32,
        space: Space,
    },
    Node(Varnode),
    Select {
        condition: Box<Self>,
        when_false: Box<Self>,
        when_true: Box<Self>,
    },
    Unary {
        input: Box<Self>,
        name: &'static str,
    },
}

impl Display for Expression {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binary { name, left, right } => write!(formatter, "{name}({left},{right})"),
            Self::Load {
                pointer,
                size_bytes,
                space,
            } => write!(formatter, "load({space},{pointer},{size_bytes})"),
            Self::Node(node) => write!(formatter, "{node}"),
            Self::Select {
                condition,
                when_false,
                when_true,
            } => write!(formatter, "select({condition},{when_true},{when_false})"),
            Self::Unary { input, name } => write!(formatter, "{name}({input})"),
        }
    }
}

#[test]
fn normalized_architectural_effects_match_ghidra_pypcode() {
    let records: &str = include_str!("corpus/aarch64_pypcode.tsv");
    let raw: &str = include_str!("corpus/aarch64_pypcode.raw");
    assert!(raw.starts_with("pypcode 4.0.0\nAARCH64:LE:64:v8A\n"));
    let raw_headers: Vec<&str> = raw
        .lines()
        .filter(|line: &&str| is_raw_header(line))
        .collect();
    let mut checked: usize = 0;
    for line in records
        .lines()
        .skip(1)
        .filter(|line: &&str| !line.is_empty())
    {
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(fields.len(), 4, "{line}");
        let raw_header: String = format!("{:0>4} {} {}", fields[0], fields[1], fields[2]);
        assert!(raw_headers.contains(&raw_header.as_str()), "{line}");
        let address: u64 = u64::from_str_radix(fields[0], 16).unwrap_or(u64::MAX);
        let word: u32 = u32::from_str_radix(fields[1], 16).unwrap_or(u32::MAX);
        let instructions: Vec<PcodeInstr> = decode_block(&word.to_le_bytes(), address);
        assert_eq!(instructions.len(), 1, "{line}");
        let Some(instruction) = instructions.first() else {
            continue;
        };
        assert_eq!(instruction.status, DecodeStatus::Supported, "{line}");
        assert_eq!(instruction.mnemonic, fields[2], "{line}");
        let joined: String = architectural_facts(&instruction.ops).join("|");
        let actual: String = if joined.is_empty() {
            "none".to_owned()
        } else {
            joined
        };
        assert_eq!(actual, fields[3], "{line}");
        checked = checked.saturating_add(1);
    }
    assert_eq!(checked, 64);
    assert_eq!(raw_headers.len(), checked);
}

fn is_raw_header(line: &str) -> bool {
    let fields: Vec<&str> = line.split_whitespace().collect();
    fields.len() == 3
        && fields[0].len() == 4
        && fields[1].len() == 8
        && fields[0]
            .chars()
            .chain(fields[1].chars())
            .all(|character: char| character.is_ascii_hexdigit())
}

fn architectural_facts(operations: &[PcodeOp]) -> Vec<String> {
    let mut values: BTreeMap<Varnode, Expression> = BTreeMap::new();
    let mut facts: Vec<String> = Vec::new();
    for operation in operations {
        match operation {
            PcodeOp::BoolAnd {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "booland",
                *left,
                *right,
                true,
                &mut values,
                &mut facts,
            ),
            PcodeOp::BoolNegate { output, input } => {
                record_unary(*output, "boolnot", *input, &mut values, &mut facts);
            }
            PcodeOp::BoolOr {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "boolor",
                *left,
                *right,
                true,
                &mut values,
                &mut facts,
            ),
            PcodeOp::BoolXor {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "boolxor",
                *left,
                *right,
                true,
                &mut values,
                &mut facts,
            ),
            PcodeOp::Branch { target } => {
                facts.push(format!("branch({})", resolve(*target, &values)));
            }
            PcodeOp::BranchIndirect { target } => {
                facts.push(format!("branchind({})", resolve(*target, &values)));
            }
            PcodeOp::CBranch { target, condition } => facts.push(format!(
                "cbranch({},{})",
                resolve(*target, &values),
                resolve(*condition, &values)
            )),
            PcodeOp::Call { target } => {
                facts.push(format!("call({})", resolve(*target, &values)));
            }
            PcodeOp::CallIndirect { target } => {
                facts.push(format!("callind({})", resolve(*target, &values)));
            }
            PcodeOp::CallOther { name, .. } => facts.push(format!("callother({name})")),
            PcodeOp::Copy { output, input } => {
                let expression: Expression = resolve(*input, &values);
                record(*output, expression, &mut values, &mut facts);
            }
            PcodeOp::IntAdd {
                output,
                left,
                right,
            } => {
                let left_expression: Expression = resolve(*left, &values);
                let right_expression: Expression = resolve(*right, &values);
                let expression: Expression = select_expression(&left_expression, &right_expression)
                    .unwrap_or_else(|| binary("add", left_expression, right_expression, true));
                record(*output, expression, &mut values, &mut facts);
            }
            PcodeOp::IntAnd {
                output,
                left,
                right,
            } => record_binary(*output, "and", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntCarry {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "carry",
                *left,
                *right,
                true,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntEqual {
                output,
                left,
                right,
            } => record_binary(*output, "eq", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntLeft {
                output,
                input,
                amount,
            } => record_binary(
                *output,
                "shl",
                *input,
                *amount,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntLess {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "ult",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntMult {
                output,
                left,
                right,
            } => record_binary(*output, "mul", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntNotEqual {
                output,
                left,
                right,
            } => record_binary(*output, "ne", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntOr {
                output,
                left,
                right,
            } => record_binary(*output, "or", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntRight {
                output,
                input,
                amount,
            } => record_binary(
                *output,
                "lshr",
                *input,
                *amount,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntSignedBorrow {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "sborrow",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntSignedCarry {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "scarry",
                *left,
                *right,
                true,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntSignedLess {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "slt",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntSignedRight {
                output,
                input,
                amount,
            } => record_binary(
                *output,
                "ashr",
                *input,
                *amount,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntSub {
                output,
                left,
                right,
            } => record_binary(
                *output,
                "sub",
                *left,
                *right,
                false,
                &mut values,
                &mut facts,
            ),
            PcodeOp::IntXor {
                output,
                left,
                right,
            } => record_binary(*output, "xor", *left, *right, true, &mut values, &mut facts),
            PcodeOp::IntZext { output, input } => {
                record_unary(*output, "zext", *input, &mut values, &mut facts);
            }
            PcodeOp::Load {
                output,
                space,
                pointer,
            } => {
                let expression: Expression = Expression::Load {
                    pointer: Box::new(resolve(*pointer, &values)),
                    size_bytes: output.size_bytes,
                    space: *space,
                };
                record(*output, expression, &mut values, &mut facts);
            }
            PcodeOp::Return { target } => {
                let rendered: String = target.map_or_else(
                    || "none".to_owned(),
                    |node: Varnode| resolve(node, &values).to_string(),
                );
                facts.push(format!("return({rendered})"));
            }
            PcodeOp::Store {
                space,
                pointer,
                value,
            } => facts.push(format!(
                "store({},{},{})",
                space,
                resolve(*pointer, &values),
                resolve(*value, &values)
            )),
            _ => facts.push(format!("unhandled({})", operation.name())),
        }
    }
    facts.sort();
    facts
}

fn record_binary(
    output: Varnode,
    name: &'static str,
    left: Varnode,
    right: Varnode,
    commutative: bool,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let expression: Expression = binary(
        name,
        resolve(left, values),
        resolve(right, values),
        commutative,
    );
    record(output, expression, values, facts);
}

fn record_unary(
    output: Varnode,
    name: &'static str,
    input: Varnode,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let resolved: Expression = resolve(input, values);
    let expression: Expression = match (&resolved, name) {
        (Expression::Node(node), "zext") if node.space == Space::Constant => {
            Expression::Node(Varnode {
                offset: node.offset,
                size_bytes: output.size_bytes,
                space: Space::Constant,
            })
        }
        _ => Expression::Unary {
            input: Box::new(resolved),
            name,
        },
    };
    record(output, expression, values, facts);
}

fn record(
    output: Varnode,
    expression: Expression,
    values: &mut BTreeMap<Varnode, Expression>,
    facts: &mut Vec<String>,
) {
    let previous: Option<Expression> = values.insert(output, expression.clone());
    drop(previous);
    if output.space == Space::Register {
        let prefix: String = format!("write({output},");
        facts.retain(|fact: &String| !fact.starts_with(&prefix));
        facts.push(format!("{prefix}{expression})"));
    }
}

fn resolve(node: Varnode, values: &BTreeMap<Varnode, Expression>) -> Expression {
    values.get(&node).cloned().unwrap_or(Expression::Node(node))
}

fn binary(
    name: &'static str,
    left: Expression,
    right: Expression,
    commutative: bool,
) -> Expression {
    let (canonical_left, canonical_right): (Expression, Expression) =
        if commutative && left.to_string() > right.to_string() {
            (right, left)
        } else {
            (left, right)
        };
    Expression::Binary {
        name,
        left: Box::new(canonical_left),
        right: Box::new(canonical_right),
    }
}

fn select_expression(left: &Expression, right: &Expression) -> Option<Expression> {
    select_order(left, right).or_else(|| select_order(right, left))
}

fn select_order(true_term: &Expression, false_term: &Expression) -> Option<Expression> {
    let (condition, when_true): (&Expression, &Expression) = select_term(true_term, false)?;
    let (inverted, when_false): (&Expression, &Expression) = select_term(false_term, true)?;
    if condition != inverted {
        return None;
    }
    Some(Expression::Select {
        condition: Box::new(condition.clone()),
        when_false: Box::new(when_false.clone()),
        when_true: Box::new(when_true.clone()),
    })
}

fn select_term(expression: &Expression, inverted: bool) -> Option<(&Expression, &Expression)> {
    let Expression::Binary {
        name: "mul",
        left,
        right,
    } = expression
    else {
        return None;
    };
    select_factor(left, right, inverted).or_else(|| select_factor(right, left, inverted))
}

fn select_factor<'a>(
    mask: &'a Expression,
    value: &'a Expression,
    inverted: bool,
) -> Option<(&'a Expression, &'a Expression)> {
    let Expression::Unary {
        input,
        name: "zext",
    } = mask
    else {
        return None;
    };
    if !inverted {
        return Some((input, value));
    }
    let Expression::Unary {
        input: condition,
        name: "boolnot",
    } = input.as_ref()
    else {
        return None;
    };
    Some((condition, value))
}
