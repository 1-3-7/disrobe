use super::biff::{read_short_xlunicode, read_u16, read_u32, read_wide_string, read_xlunicode};
use super::ftab::{cetab_name, ftab_fixed_argc, ftab_name};
use super::limits::{MAX_ARRAY_VALUES, MAX_STACK_DEPTH, MAX_TOKENS};
use super::scope::XtiScope;

pub const UNKNOWN_MARKER: &str = "[[xlm-unknown-token]]";

fn unknown_function(iftab: u16) -> String {
    format!("[[xlm-unknown-function:{iftab:#06X}]]")
}

fn unknown_command(cetab: u16) -> String {
    format!("[[xlm-unknown-command:{cetab:#06X}]]")
}

fn unknown_arity(name: &str) -> String {
    format!("[[xlm-unknown-arity:{name}]]")
}

fn unknown_defined_name(index: u32) -> String {
    format!("[[xlm-unknown-name:{index}]]")
}

fn unknown_extern_name(index: u32) -> String {
    format!("[[xlm-unknown-extern-name:{index}]]")
}

const PREC_CMP: u8 = 1;
const PREC_CONCAT: u8 = 2;
const PREC_ADD: u8 = 3;
const PREC_MUL: u8 = 4;
const PREC_POW: u8 = 5;
const PREC_UNARY: u8 = 6;
const PREC_PCT: u8 = 7;
const PREC_REF: u8 = 8;
const PREC_ATOM: u8 = 100;

const COL_MASK: u16 = 0x3FFF;
const COL_REL: u16 = 0x4000;
const ROW_REL: u16 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiffVersion {
    Biff8,
    Biff12,
}

impl BiffVersion {
    fn loc_size(self) -> usize {
        match self {
            Self::Biff8 => 4,
            Self::Biff12 => 6,
        }
    }

    fn area_size(self) -> usize {
        match self {
            Self::Biff8 => 8,
            Self::Biff12 => 12,
        }
    }

    fn row_count(self) -> u32 {
        match self {
            Self::Biff8 => 0x0001_0000,
            Self::Biff12 => 0x0010_0000,
        }
    }

    fn col_count(self) -> u32 {
        match self {
            Self::Biff8 => 0x0000_0100,
            Self::Biff12 => 0x0000_4000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PtgContext<'a> {
    pub version: BiffVersion,
    pub base_row: u32,
    pub base_col: u32,
    pub names: &'a [String],
    pub scope: &'a XtiScope,
}

#[derive(Debug)]
struct Extra<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Extra<'_> {
    fn take(&mut self, len: usize) -> Option<&[u8]> {
        let end: usize = self.pos.checked_add(len)?;
        let slice: &[u8] = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }
}

#[derive(Debug, Clone)]
pub struct DecodedFormula {
    pub text: String,
    pub unknown: bool,
}

#[derive(Debug, Clone)]
struct Operand {
    text: String,
    prec: u8,
}

pub fn parse_ptg_exp(rgce: &[u8], version: BiffVersion) -> Option<(u32, u32)> {
    if rgce.first().copied()? != 0x01 {
        return None;
    }
    match version {
        BiffVersion::Biff8 => {
            let row: u32 = u32::from(read_u16(rgce, 1)?);
            let col: u32 = u32::from(read_u16(rgce, 3)?);
            Some((row, col))
        }
        BiffVersion::Biff12 => {
            let row: u32 = read_u32(rgce, 1)?;
            let col: u32 = read_u32(rgce, 5)?;
            Some((row, col))
        }
    }
}

pub fn decode_rgce(rgce: &[u8], ctx: &PtgContext<'_>) -> DecodedFormula {
    decode_formula(rgce, &[], ctx)
}

pub fn decode_formula(rgce: &[u8], rgcb: &[u8], ctx: &PtgContext<'_>) -> DecodedFormula {
    let mut stack: Vec<Operand> = Vec::new();
    let mut extra: Extra<'_> = Extra { data: rgcb, pos: 0 };
    let mut pos: usize = 0;
    let mut tokens: usize = 0;
    let mut aborted: bool = false;
    let mut degraded: bool = false;
    while pos < rgce.len() {
        if tokens >= MAX_TOKENS || stack.len() > MAX_STACK_DEPTH {
            aborted = true;
            break;
        }
        tokens += 1;
        let byte: u8 = rgce[pos];
        let step: Option<usize> =
            apply_token(byte, rgce, pos, ctx, &mut extra, &mut stack, &mut degraded);
        match step {
            Some(consumed) if consumed > 0 => pos += consumed,
            _ => {
                aborted = true;
                break;
            }
        }
    }
    finalize(stack, aborted, degraded)
}

pub fn token_base_codes(rgce: &[u8], rgcb: &[u8], ctx: &PtgContext<'_>) -> Vec<(usize, u8)> {
    let mut stack: Vec<Operand> = Vec::new();
    let mut extra: Extra<'_> = Extra { data: rgcb, pos: 0 };
    let mut pos: usize = 0;
    let mut tokens: usize = 0;
    let mut degraded: bool = false;
    let mut codes: Vec<(usize, u8)> = Vec::new();
    while pos < rgce.len() {
        if tokens >= MAX_TOKENS || stack.len() > MAX_STACK_DEPTH {
            break;
        }
        tokens += 1;
        let byte: u8 = rgce[pos];
        let code: u8 = if byte >= 0x20 {
            0x20 | (byte & 0x1F)
        } else {
            byte
        };
        let step: Option<usize> =
            apply_token(byte, rgce, pos, ctx, &mut extra, &mut stack, &mut degraded);
        match step {
            Some(consumed) if consumed > 0 => {
                codes.push((pos, code));
                pos += consumed;
            }
            _ => break,
        }
    }
    codes
}

fn finalize(mut stack: Vec<Operand>, aborted: bool, degraded: bool) -> DecodedFormula {
    if !aborted && stack.len() == 1 {
        return DecodedFormula {
            text: stack.remove(0).text,
            unknown: degraded,
        };
    }
    let mut text: String = stack
        .into_iter()
        .map(|op: Operand| op.text)
        .collect::<Vec<String>>()
        .join(" ");
    if !text.is_empty() {
        text.push(' ');
    }
    text.push_str(UNKNOWN_MARKER);
    DecodedFormula {
        text,
        unknown: true,
    }
}

fn apply_token(
    byte: u8,
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    extra: &mut Extra<'_>,
    stack: &mut Vec<Operand>,
    degraded: &mut bool,
) -> Option<usize> {
    match byte {
        0x01 | 0x02 => Some(if ctx.version == BiffVersion::Biff8 {
            5
        } else {
            9
        }),
        0x03..=0x11 => binary_operator(byte, stack),
        0x12 | 0x13 => unary_prefix(byte, stack),
        0x14 => percent(stack),
        0x15 => paren(stack),
        0x16 => {
            push(stack, String::new(), PREC_ATOM);
            Some(1)
        }
        0x17 => ptg_str(rgce, pos, ctx, stack),
        0x18 => elf_token(rgce, pos),
        0x19 => attr_token(rgce, pos, stack),
        0x1C => ptg_err(rgce, pos, stack),
        0x1D => ptg_bool(rgce, pos, stack),
        0x1E => ptg_int(rgce, pos, stack),
        0x1F => ptg_num(rgce, pos, stack),
        _ if byte >= 0x20 => classed_token(byte, rgce, pos, ctx, extra, stack, degraded),
        _ => None,
    }
}

fn push(stack: &mut Vec<Operand>, text: String, prec: u8) {
    stack.push(Operand { text, prec });
}

fn wrap(op: &Operand, min_prec: u8) -> String {
    if op.prec < min_prec {
        format!("({})", op.text)
    } else {
        op.text.clone()
    }
}

fn binary_operator(byte: u8, stack: &mut Vec<Operand>) -> Option<usize> {
    let (symbol, prec): (&str, u8) = match byte {
        0x03 => ("+", PREC_ADD),
        0x04 => ("-", PREC_ADD),
        0x05 => ("*", PREC_MUL),
        0x06 => ("/", PREC_MUL),
        0x07 => ("^", PREC_POW),
        0x08 => ("&", PREC_CONCAT),
        0x09 => ("<", PREC_CMP),
        0x0A => ("<=", PREC_CMP),
        0x0B => ("=", PREC_CMP),
        0x0C => (">=", PREC_CMP),
        0x0D => (">", PREC_CMP),
        0x0E => ("<>", PREC_CMP),
        0x0F => (" ", PREC_REF),
        0x10 => (",", PREC_REF),
        0x11 => (":", PREC_REF),
        _ => return None,
    };
    let right: Operand = stack.pop()?;
    let left: Operand = stack.pop()?;
    let text: String = format!("{}{}{}", wrap(&left, prec), symbol, wrap(&right, prec + 1));
    push(stack, text, prec);
    Some(1)
}

fn unary_prefix(byte: u8, stack: &mut Vec<Operand>) -> Option<usize> {
    let symbol: &str = if byte == 0x12 { "+" } else { "-" };
    let operand: Operand = stack.pop()?;
    let text: String = format!("{}{}", symbol, wrap(&operand, PREC_UNARY));
    push(stack, text, PREC_UNARY);
    Some(1)
}

fn percent(stack: &mut Vec<Operand>) -> Option<usize> {
    let operand: Operand = stack.pop()?;
    let text: String = format!("{}%", wrap(&operand, PREC_PCT));
    push(stack, text, PREC_PCT);
    Some(1)
}

fn paren(stack: &mut Vec<Operand>) -> Option<usize> {
    let operand: Operand = stack.pop()?;
    push(stack, format!("({})", operand.text), PREC_ATOM);
    Some(1)
}

fn ptg_str(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
) -> Option<usize> {
    let (raw, consumed): (String, usize) = match ctx.version {
        BiffVersion::Biff8 => read_short_xlunicode(rgce, pos + 1)?,
        BiffVersion::Biff12 => read_wide_string(rgce, pos + 1)?,
    };
    push(stack, quote(&raw), PREC_ATOM);
    Some(1 + consumed)
}

fn quote(raw: &str) -> String {
    format!("\"{}\"", raw.replace('"', "\"\""))
}

fn elf_token(rgce: &[u8], pos: usize) -> Option<usize> {
    let sub: u8 = *rgce.get(pos + 1)?;
    match sub {
        0x01 | 0x02 | 0x03 | 0x06 | 0x07 | 0x0A | 0x0B | 0x0D | 0x0F | 0x10 | 0x1D => Some(4),
        _ => None,
    }
}

fn attr_token(rgce: &[u8], pos: usize, stack: &mut Vec<Operand>) -> Option<usize> {
    let grbit: u8 = *rgce.get(pos + 1)?;
    if grbit & 0x04 != 0 {
        let count: usize = read_u16(rgce, pos + 2)? as usize;
        let table: usize = count.checked_add(1)?.checked_mul(2)?;
        return 4usize.checked_add(table);
    }
    if grbit & 0x10 != 0 {
        let operand: Operand = stack.pop()?;
        push(stack, format!("SUM({})", operand.text), PREC_ATOM);
    }
    Some(4)
}

fn ptg_err(rgce: &[u8], pos: usize, stack: &mut Vec<Operand>) -> Option<usize> {
    let code: u8 = *rgce.get(pos + 1)?;
    push(stack, error_text(code).to_owned(), PREC_ATOM);
    Some(2)
}

fn error_text(code: u8) -> &'static str {
    match code {
        0x00 => "#NULL!",
        0x07 => "#DIV/0!",
        0x0F => "#VALUE!",
        0x17 => "#REF!",
        0x1D => "#NAME?",
        0x24 => "#NUM!",
        0x2A => "#N/A",
        _ => "#ERR!",
    }
}

fn ptg_bool(rgce: &[u8], pos: usize, stack: &mut Vec<Operand>) -> Option<usize> {
    let value: u8 = *rgce.get(pos + 1)?;
    let text: &str = if value == 0 { "FALSE" } else { "TRUE" };
    push(stack, text.to_owned(), PREC_ATOM);
    Some(2)
}

fn ptg_int(rgce: &[u8], pos: usize, stack: &mut Vec<Operand>) -> Option<usize> {
    let value: u16 = read_u16(rgce, pos + 1)?;
    push(stack, value.to_string(), PREC_ATOM);
    Some(3)
}

fn ptg_num(rgce: &[u8], pos: usize, stack: &mut Vec<Operand>) -> Option<usize> {
    let end: usize = pos.checked_add(9)?;
    let slice: &[u8] = rgce.get(pos + 1..end)?;
    let bytes: [u8; 8] = slice.try_into().ok()?;
    let value: f64 = f64::from_le_bytes(bytes);
    push(stack, format_number(value), PREC_ATOM);
    Some(9)
}

fn format_number(value: f64) -> String {
    if value.is_finite() {
        format!("{value}")
    } else {
        "0".to_owned()
    }
}

fn classed_token(
    byte: u8,
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    extra: &mut Extra<'_>,
    stack: &mut Vec<Operand>,
    degraded: &mut bool,
) -> Option<usize> {
    let base: u8 = byte & 0x1F;
    match base {
        0x00 => array_token(ctx, extra, stack),
        0x01 => func_fixed(rgce, pos, stack, degraded),
        0x02 => func_var(rgce, pos, stack, degraded),
        0x03 => name_token(rgce, pos, ctx, stack, degraded),
        0x04 => ref_token(rgce, pos, ctx, stack, false),
        0x05 => area_token(rgce, pos, ctx, stack, false),
        0x06 | 0x08 => mem_area(ctx, extra),
        0x07 => Some(MEM_TOKEN_SIZE),
        0x09 => mem_func(rgce, pos),
        0x0A => ref_err(rgce, pos, ctx, stack),
        0x0B => area_err(rgce, pos, ctx, stack),
        0x0C => ref_token(rgce, pos, ctx, stack, true),
        0x0D => area_token(rgce, pos, ctx, stack, true),
        0x19 => name_x_token(rgce, pos, ctx, stack, degraded),
        0x1A => ref3d_token(rgce, pos, ctx, stack, false),
        0x1B => area3d_token(rgce, pos, ctx, stack, false),
        0x1C => ref_err3d(rgce, pos, ctx, stack),
        0x1D => area_err3d(rgce, pos, ctx, stack),
        _ => None,
    }
}

const ARRAY_TOKEN_SIZE: usize = 8;
const MEM_TOKEN_SIZE: usize = 7;
const REF8U_SIZE: usize = 8;

fn array_token(
    ctx: &PtgContext<'_>,
    extra: &mut Extra<'_>,
    stack: &mut Vec<Operand>,
) -> Option<usize> {
    if ctx.version != BiffVersion::Biff8 {
        return None;
    }
    let text: String = read_array_constant(extra)?;
    push(stack, text, PREC_ATOM);
    Some(ARRAY_TOKEN_SIZE)
}

fn read_array_constant(extra: &mut Extra<'_>) -> Option<String> {
    let header: &[u8] = extra.take(3)?;
    let cols: usize = usize::from(header[0]) + 1;
    let rows: usize = usize::from(u16::from_le_bytes([header[1], header[2]])) + 1;
    if cols.checked_mul(rows)? > MAX_ARRAY_VALUES {
        return None;
    }
    let mut lines: Vec<String> = Vec::with_capacity(rows);
    for _ in 0..rows {
        let mut cells: Vec<String> = Vec::with_capacity(cols);
        for _ in 0..cols {
            cells.push(read_array_value(extra)?);
        }
        lines.push(cells.join(","));
    }
    Some(format!("{{{}}}", lines.join(";")))
}

fn read_array_value(extra: &mut Extra<'_>) -> Option<String> {
    let kind: u8 = extra.take(1)?[0];
    match kind {
        0x00 => extra.take(8).map(|_unused: &[u8]| String::new()),
        0x01 => {
            let bytes: [u8; 8] = extra.take(8)?.try_into().ok()?;
            Some(format_number(f64::from_le_bytes(bytes)))
        }
        0x02 => {
            let (text, consumed): (String, usize) = read_xlunicode(extra.data, extra.pos)?;
            extra.take(consumed)?;
            Some(quote(&text))
        }
        0x04 => {
            let raw: u8 = extra.take(8)?[0];
            Some(if raw == 0 { "FALSE" } else { "TRUE" }.to_owned())
        }
        0x10 => {
            let raw: u8 = extra.take(8)?[0];
            Some(error_text(raw).to_owned())
        }
        _ => None,
    }
}

const FTAB_USER_FUNCTION: u16 = 0x00FF;
const FUTURE_FUNCTION_PREFIX: &str = "_xlfn.";

fn func_fixed(
    rgce: &[u8],
    pos: usize,
    stack: &mut Vec<Operand>,
    degraded: &mut bool,
) -> Option<usize> {
    let iftab: u16 = read_u16(rgce, pos + 1)?;
    let Some(argc): Option<u8> = ftab_fixed_argc(iftab) else {
        *degraded = true;
        let text: String = ftab_name(iftab).map_or_else(|| unknown_function(iftab), unknown_arity);
        push(stack, text, PREC_ATOM);
        return Some(3);
    };
    let rendered: String = render_ftab_call(iftab, argc as usize, stack, degraded)?;
    push(stack, rendered, PREC_ATOM);
    Some(3)
}

fn func_var(
    rgce: &[u8],
    pos: usize,
    stack: &mut Vec<Operand>,
    degraded: &mut bool,
) -> Option<usize> {
    let cparams: usize = usize::from(*rgce.get(pos + 1)?);
    let raw: u16 = read_u16(rgce, pos + 2)?;
    let is_command: bool = raw & 0x8000 != 0;
    let tab: u16 = raw & 0x7FFF;
    let rendered: String = if is_command {
        let name: String = cetab_name(tab).map_or_else(
            || {
                *degraded = true;
                unknown_command(tab)
            },
            str::to_owned,
        );
        render_call(&name, cparams, stack)?
    } else {
        render_ftab_call(tab, cparams, stack, degraded)?
    };
    push(stack, rendered, PREC_ATOM);
    Some(4)
}

fn render_ftab_call(
    iftab: u16,
    argc: usize,
    stack: &mut Vec<Operand>,
    degraded: &mut bool,
) -> Option<String> {
    if iftab == FTAB_USER_FUNCTION && argc > 0 {
        return render_user_function(argc, stack);
    }
    let name: String = ftab_name(iftab).map_or_else(
        || {
            *degraded = true;
            unknown_function(iftab)
        },
        str::to_owned,
    );
    render_call(&name, argc, stack)
}

fn render_user_function(argc: usize, stack: &mut Vec<Operand>) -> Option<String> {
    let mut args: Vec<String> = pop_args(argc, stack)?;
    let callee: String = args.remove(0);
    let name: &str = callee
        .strip_prefix(FUTURE_FUNCTION_PREFIX)
        .unwrap_or(&callee);
    Some(format!("{name}({})", args.join(",")))
}

fn render_call(name: &str, argc: usize, stack: &mut Vec<Operand>) -> Option<String> {
    let args: Vec<String> = pop_args(argc, stack)?;
    Some(format!("{name}({})", args.join(",")))
}

fn pop_args(argc: usize, stack: &mut Vec<Operand>) -> Option<Vec<String>> {
    if stack.len() < argc {
        return None;
    }
    let split: usize = stack.len() - argc;
    Some(
        stack
            .split_off(split)
            .into_iter()
            .map(|op: Operand| op.text)
            .collect(),
    )
}

fn name_token(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
    degraded: &mut bool,
) -> Option<usize> {
    let index: u32 = read_u32(rgce, pos + 1)?;
    let resolved: Option<&String> = usize::try_from(index)
        .ok()
        .and_then(|idx: usize| idx.checked_sub(1))
        .and_then(|at: usize| ctx.names.get(at))
        .filter(|name: &&String| !name.is_empty());
    let text: String = resolved.map_or_else(
        || {
            *degraded = true;
            unknown_defined_name(index)
        },
        String::clone,
    );
    push(stack, text, PREC_ATOM);
    Some(5)
}

fn name_x_token(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
    degraded: &mut bool,
) -> Option<usize> {
    let ixti: u16 = read_u16(rgce, pos + 1)?;
    let index: u32 = read_u32(rgce, pos + 3)?;
    let text: String = ctx
        .scope
        .extern_name(ixti, index)
        .filter(|name: &&str| !name.is_empty())
        .map_or_else(
            || {
                *degraded = true;
                unknown_extern_name(index)
            },
            str::to_owned,
        );
    push(stack, text, PREC_ATOM);
    Some(7)
}

fn ref_token(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
    relative: bool,
) -> Option<usize> {
    let (text, size): (String, usize) = read_loc(rgce, pos + 1, ctx, relative)?;
    push(stack, text, PREC_ATOM);
    Some(1 + size)
}

fn ref_err(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
) -> Option<usize> {
    let size: usize = ctx.version.loc_size();
    rgce.get(pos + 1..pos + 1 + size)?;
    push(stack, "#REF!".to_owned(), PREC_ATOM);
    Some(1 + size)
}

fn area_token(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
    relative: bool,
) -> Option<usize> {
    let (text, size): (String, usize) = read_area(rgce, pos + 1, ctx, relative)?;
    push(stack, text, PREC_ATOM);
    Some(1 + size)
}

fn area_err(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
) -> Option<usize> {
    let size: usize = ctx.version.area_size();
    rgce.get(pos + 1..pos + 1 + size)?;
    push(stack, "#REF!".to_owned(), PREC_ATOM);
    Some(1 + size)
}

fn ref3d_token(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
    relative: bool,
) -> Option<usize> {
    let ixti: u16 = read_u16(rgce, pos + 1)?;
    let (text, size): (String, usize) = read_loc(rgce, pos + 3, ctx, relative)?;
    push(stack, qualify(ctx, ixti, &text), PREC_ATOM);
    Some(3 + size)
}

fn ref_err3d(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
) -> Option<usize> {
    let size: usize = 2usize.checked_add(ctx.version.loc_size())?;
    rgce.get(pos + 1..pos + 1 + size)?;
    push(stack, "#REF!".to_owned(), PREC_ATOM);
    Some(1 + size)
}

fn area_err3d(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
) -> Option<usize> {
    let size: usize = 2usize.checked_add(ctx.version.area_size())?;
    rgce.get(pos + 1..pos + 1 + size)?;
    push(stack, "#REF!".to_owned(), PREC_ATOM);
    Some(1 + size)
}

fn qualify(ctx: &PtgContext<'_>, ixti: u16, text: &str) -> String {
    match ctx.scope.sheet_label(ixti) {
        Some(label) => format!("{label}!{text}"),
        None => format!("[{ixti}]!{text}"),
    }
}

fn area3d_token(
    rgce: &[u8],
    pos: usize,
    ctx: &PtgContext<'_>,
    stack: &mut Vec<Operand>,
    relative: bool,
) -> Option<usize> {
    let ixti: u16 = read_u16(rgce, pos + 1)?;
    let (text, size): (String, usize) = read_area(rgce, pos + 3, ctx, relative)?;
    push(stack, qualify(ctx, ixti, &text), PREC_ATOM);
    Some(3 + size)
}

fn mem_area(ctx: &PtgContext<'_>, extra: &mut Extra<'_>) -> Option<usize> {
    if ctx.version == BiffVersion::Biff8 && !extra.data.is_empty() {
        let count: usize = usize::from(u16::from_le_bytes(extra.take(2)?.try_into().ok()?));
        extra.take(count.checked_mul(REF8U_SIZE)?)?;
    }
    Some(MEM_TOKEN_SIZE)
}

fn mem_func(rgce: &[u8], pos: usize) -> Option<usize> {
    read_u16(rgce, pos + 1)?;
    Some(3)
}

fn read_loc(
    rgce: &[u8],
    at: usize,
    ctx: &PtgContext<'_>,
    relative: bool,
) -> Option<(String, usize)> {
    match ctx.version {
        BiffVersion::Biff8 => {
            let row: u16 = read_u16(rgce, at)?;
            let col_field: u16 = read_u16(rgce, at + 2)?;
            Some((format_ref(u32::from(row), col_field, ctx, relative), 4))
        }
        BiffVersion::Biff12 => {
            let row: u32 = read_u32(rgce, at)?;
            let col_field: u16 = read_u16(rgce, at + 4)?;
            Some((format_ref(row, col_field, ctx, relative), 6))
        }
    }
}

fn read_area(
    rgce: &[u8],
    at: usize,
    ctx: &PtgContext<'_>,
    relative: bool,
) -> Option<(String, usize)> {
    match ctx.version {
        BiffVersion::Biff8 => {
            let row_first: u16 = read_u16(rgce, at)?;
            let row_last: u16 = read_u16(rgce, at + 2)?;
            let col_first: u16 = read_u16(rgce, at + 4)?;
            let col_last: u16 = read_u16(rgce, at + 6)?;
            let first: String = format_ref(u32::from(row_first), col_first, ctx, relative);
            let last: String = format_ref(u32::from(row_last), col_last, ctx, relative);
            Some((format!("{first}:{last}"), 8))
        }
        BiffVersion::Biff12 => {
            let row_first: u32 = read_u32(rgce, at)?;
            let row_last: u32 = read_u32(rgce, at + 4)?;
            let col_first: u16 = read_u16(rgce, at + 8)?;
            let col_last: u16 = read_u16(rgce, at + 10)?;
            let first: String = format_ref(row_first, col_first, ctx, relative);
            let last: String = format_ref(row_last, col_last, ctx, relative);
            Some((format!("{first}:{last}"), 12))
        }
    }
}

fn format_ref(row: u32, col_field: u16, ctx: &PtgContext<'_>, relative: bool) -> String {
    let col_rel: bool = col_field & COL_REL != 0;
    let row_rel: bool = col_field & ROW_REL != 0;
    let col_raw: u32 = u32::from(col_field & COL_MASK);
    let (abs_row, abs_col): (u32, u32) = if relative {
        (
            resolve_relative(ctx.base_row, row, row_rel, ctx.version.row_count()),
            resolve_relative(ctx.base_col, col_raw, col_rel, ctx.version.col_count()),
        )
    } else {
        (row, col_raw)
    };
    let col_prefix: &str = if col_rel { "" } else { "$" };
    let row_prefix: &str = if row_rel { "" } else { "$" };
    format!(
        "{col_prefix}{}{row_prefix}{}",
        column_letters(abs_col),
        abs_row + 1
    )
}

fn resolve_relative(base: u32, stored: u32, is_relative: bool, dimension: u32) -> u32 {
    if !is_relative {
        return stored;
    }
    let sum: u64 = u64::from(base) + u64::from(stored);
    (sum % u64::from(dimension)) as u32
}

pub fn column_letters(col: u32) -> String {
    let mut n: u32 = col;
    let mut letters: Vec<u8> = Vec::new();
    loop {
        let remainder: u32 = n % 26;
        letters.push(b'A' + remainder as u8);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    letters.reverse();
    String::from_utf8_lossy(&letters).into_owned()
}
