//! Clean-room YARV IBF (`YARB`) image reader: object/literal pool plus iseq opcode-body lifting.

use serde::{Deserialize, Serialize};

use crate::yarv::opcodes::{TsKind, YarvOpcode, YarvVersion};
use crate::yarv::reader::YarvBinaryHeader;

pub(crate) const IBF_OBJECT_LIST_ENTRY_CAP: u32 = 1_048_576;
pub(crate) const IBF_STRING_LEN_CAP: usize = 16 * 1024 * 1024;
pub(crate) const IBF_ARRAY_LEN_CAP: usize = 1_048_576;
const IBF_MAX_INSNS_PER_ISEQ: usize = 1_048_576;
const IBF_MAX_ISEQ_BODIES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IbfObjectKind {
    String,
    Symbol,
    Array,
    Bignum,
    Float,
    Regexp,
    Hash,
    Struct,
    Class,
    Object,
    Complex,
    Rational,
    Nil,
    True,
    False,
    Fixnum,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IbfObject {
    pub index: u32,
    pub offset: u32,
    pub kind: IbfObjectKind,
    pub literal: Option<String>,
    pub element_count: Option<u32>,
    /// Object-table indices of an `Array` object's elements, used to resolve a constant-path cache.
    pub elements: Vec<u32>,
}

/// One decoded YARV instruction within an iseq body, with operands resolved against the object /
/// iseq tables where the operand kind allows it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvIbfInstruction {
    pub pc: u32,
    pub opcode: u32,
    pub mnemonic: String,
    pub operands: Vec<YarvOperand>,
}

/// A single resolved YARV operand value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum YarvOperand {
    /// A resolved string literal recovered from the object table (rendered quoted).
    Literal(String),
    /// A resolved numeric literal (Fixnum/Float) recovered from the object table (rendered bare).
    NumLiteral(String),
    /// An object-table index whose object carried no recoverable literal.
    ObjectRef(u32),
    /// A nested iseq-table index.
    IseqRef(u32),
    /// A resolved method/name id (symbol object).
    Id(String),
    /// A branch target (raw dumped offset value).
    Offset(u32),
    /// A raw integer operand (`TS_NUM` / cache slot).
    Num(u64),
    /// A resolved builtin-function name.
    Builtin(String),
    /// A resolved call site recovered from the iseq `ci_entries`: method name and argument count.
    Call { method: String, argc: u32 },
}

/// One recovered call-site descriptor from an iseq body's `ci_entries` block.
#[derive(Debug, Clone)]
struct CallEntry {
    method: Option<String>,
    argc: u32,
}

/// The handler kind of a `catch_table` entry (`enum rb_catch_type`, dumped as `INT2FIX(n)`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CatchType {
    Rescue,
    Ensure,
    Retry,
    Break,
    Redo,
    Next,
    Unknown,
}

/// One decoded `catch_table` entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvCatchEntry {
    pub catch_type: CatchType,
    pub start_pc: u32,
    pub end_pc: u32,
    pub cont_pc: u32,
    pub handler_iseq: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct YarvIseqBody {
    pub index: u32,
    pub offset: u32,
    pub iseq_size: u32,
    pub instructions: Vec<YarvIbfInstruction>,
    /// Local-variable names recovered from this body's `local_table`, in table order. An entry is
    /// `None` when the slot is a compiler-hidden local (dumped as an integer rather than a symbol).
    pub local_table: Vec<Option<String>>,
    /// Number of leading required positional parameters (`param.lead_num`); the block/method
    /// parameter names are the first `param_lead_num` entries of `local_table`.
    pub param_lead_num: u32,
    /// Decoded `catch_table` entries (rescue/ensure/retry/break/redo/next protected regions).
    pub catch_entries: Vec<YarvCatchEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IbfImage {
    pub iseq_offsets: Vec<u32>,
    pub objects: Vec<IbfObject>,
    pub iseqs: Vec<YarvIseqBody>,
    pub recovered_literal_count: u32,
    pub recovered_instruction_count: u32,
}

#[inline]
const fn ntz_u8(c: u8) -> u32 {
    if c == 0 { 8 } else { c.trailing_zeros() }
}

/// Decode one `small_value` varint at `pos`, returning the value and the next position. Ports the
/// exact `ibf_load_small_value` algorithm; rejects (returns `None`) on a run past `bytes`.
#[inline]
#[allow(clippy::many_single_char_names)]
pub(crate) fn read_small_value(bytes: &[u8], pos: usize) -> Option<(u64, usize)> {
    let c: u8 = *bytes.get(pos)?;
    let n: usize = if c & 1 == 1 {
        1
    } else if c == 0 {
        9
    } else {
        (ntz_u8(c) as usize) + 1
    };
    let end: usize = pos.checked_add(n)?;
    if end > bytes.len() {
        return None;
    }
    let mut x: u64 = if n >= 9 {
        0
    } else {
        u64::from(c) >> (n as u32)
    };
    let mut i: usize = 1;
    while i < n {
        let b: u8 = *bytes.get(pos + i)?;
        x = (x << 8) | u64::from(b);
        i += 1;
    }
    Some((x, end))
}

#[inline]
fn read_u32_le(bytes: &[u8], pos: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(pos..pos.checked_add(4)?)?;
    let arr: [u8; 4] = slice.try_into().ok()?;
    Some(u32::from_le_bytes(arr))
}

const fn classify_tag(tag: u8) -> IbfObjectKind {
    match tag & 0x1f {
        0x01 => IbfObjectKind::Object,
        0x02 => IbfObjectKind::Class,
        0x04 => IbfObjectKind::Float,
        0x05 => IbfObjectKind::String,
        0x06 => IbfObjectKind::Regexp,
        0x07 => IbfObjectKind::Array,
        0x08 => IbfObjectKind::Hash,
        0x09 => IbfObjectKind::Struct,
        0x0a => IbfObjectKind::Bignum,
        0x0e => IbfObjectKind::Complex,
        0x0f => IbfObjectKind::Rational,
        0x11 => IbfObjectKind::Nil,
        0x12 => IbfObjectKind::True,
        0x13 => IbfObjectKind::False,
        0x14 => IbfObjectKind::Symbol,
        0x15 => IbfObjectKind::Fixnum,
        _ => IbfObjectKind::Unknown,
    }
}

/// Decode a special-const `Fixnum` whose dumped `small_value` is the raw `VALUE` `(n << 1) | 1`.
#[inline]
const fn fixnum_value(raw: u64) -> i64 {
    (raw as i64) >> 1
}

fn decode_object(bytes: &[u8], index: u32, offset: u32) -> IbfObject {
    let off: usize = offset as usize;
    let tag: u8 = bytes.get(off).copied().unwrap_or(0);
    let kind: IbfObjectKind = classify_tag(tag);
    let after_tag: usize = off.saturating_add(1);
    let mut literal: Option<String> = None;
    let mut element_count: Option<u32> = None;
    let mut elements: Vec<u32> = Vec::new();
    match kind {
        IbfObjectKind::String | IbfObjectKind::Symbol => {
            if let Some((_enc, p1)) = read_small_value(bytes, after_tag)
                && let Some((len, p2)) = read_small_value(bytes, p1)
            {
                let len_usize: usize = usize::try_from(len).unwrap_or(usize::MAX);
                if len_usize <= IBF_STRING_LEN_CAP
                    && let Some(slice) = bytes.get(p2..p2.saturating_add(len_usize))
                {
                    literal = Some(String::from_utf8_lossy(slice).into_owned());
                }
            }
        }
        IbfObjectKind::Array => {
            if let Some((count, mut ep)) = read_small_value(bytes, after_tag) {
                let capped: u32 =
                    u32::try_from(count.min(IBF_ARRAY_LEN_CAP as u64)).unwrap_or(u32::MAX);
                element_count = Some(capped);
                elements.reserve((capped as usize).min(64));
                for _ in 0..capped {
                    let Some((elem, next)): Option<(u64, usize)> = read_small_value(bytes, ep)
                    else {
                        break;
                    };
                    elements.push(u32::try_from(elem).unwrap_or(u32::MAX));
                    ep = next;
                }
            }
        }
        IbfObjectKind::Fixnum => {
            if let Some((raw, _)) = read_small_value(bytes, after_tag) {
                literal = Some(fixnum_value(raw).to_string());
            }
        }
        IbfObjectKind::Regexp => {
            let src_pos: usize = after_tag.saturating_add(1);
            if let Some((src_index, _)) = read_small_value(bytes, src_pos) {
                elements.push(u32::try_from(src_index).unwrap_or(u32::MAX));
            }
        }
        _ => {}
    }
    IbfObject {
        index,
        offset,
        kind,
        literal,
        element_count,
        elements,
    }
}

/// Resolve each `Regexp` object's literal `/source/` from its dumped source-string object index
/// (stored in `elements[0]`), in a post-pass once all string objects are decoded.
fn resolve_regexp_literals(objects: &mut [IbfObject], recovered: &mut u32) {
    let sources: Vec<Option<String>> = objects
        .iter()
        .map(|o| {
            if o.kind == IbfObjectKind::Regexp {
                o.elements
                    .first()
                    .and_then(|&src| objects.get(src as usize))
                    .filter(|s| s.kind == IbfObjectKind::String)
                    .and_then(|s| s.literal.clone())
            } else {
                None
            }
        })
        .collect();
    for (obj, src) in objects.iter_mut().zip(sources) {
        if let Some(src) = src
            && obj.literal.is_none()
            && !src.contains(['\n', '\r'])
        {
            obj.literal = Some(format!("/{}/", escape_regexp_slashes(&src)));
            *recovered = recovered.saturating_add(1);
        }
    }
}

/// Escape unescaped `/` delimiters in a regexp source so it round-trips as a `/.../` literal.
fn escape_regexp_slashes(src: &str) -> String {
    let mut out: String = String::with_capacity(src.len() + 4);
    let mut prev_backslash: bool = false;
    for ch in src.chars() {
        if ch == '/' && !prev_backslash {
            out.push('\\');
        }
        out.push(ch);
        prev_backslash = ch == '\\' && !prev_backslash;
    }
    out
}

struct ObjectTable<'a> {
    objects: &'a [IbfObject],
}

impl ObjectTable<'_> {
    fn literal(&self, index: u64) -> Option<&str> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.objects.get(i))
            .and_then(|o| o.literal.as_deref())
    }

    /// The object's recovered literal together with whether it should render bare (unquoted): a
    /// numeric Fixnum/Float, or a Regexp whose literal already carries its `/.../` delimiters.
    fn typed_literal(&self, index: u64) -> Option<(&str, bool)> {
        let obj: &IbfObject = usize::try_from(index)
            .ok()
            .and_then(|i| self.objects.get(i))?;
        let lit: &str = obj.literal.as_deref()?;
        let bare: bool = matches!(
            obj.kind,
            IbfObjectKind::Fixnum | IbfObjectKind::Float | IbfObjectKind::Regexp
        );
        Some((lit, bare))
    }
}

/// 0-indexed positions of the `small_values` within an iseq body header.
const BODY_READ_PARAM_LEAD_NUM: usize = 6;
const BODY_READ_CATCH_TABLE_SIZE: usize = 27;
const BODY_READ_CATCH_TABLE_OFFSET: usize = 28;
const BODY_READ_LOCAL_TABLE_OFFSET: usize = 26;
const BODY_READ_CI_ENTRIES_OFFSET: usize = 32;
const BODY_READ_LOCAL_TABLE_SIZE: usize = 35;
const BODY_READ_CI_SIZE: usize = 40;
const BODY_HEADER_READS: usize = 41;
const IBF_MAX_CI_ENTRIES: usize = 1_048_576;
const IBF_MAX_LOCALS: usize = 65_536;
const IBF_MAX_CATCH_ENTRIES: usize = 65_536;

struct BodyHeader {
    iseq_size: usize,
    bytecode_offset: usize,
    bytecode_size: usize,
    param_lead_num: u32,
    local_table_offset: Option<usize>,
    local_table_size: usize,
    ci_entries_offset: Option<usize>,
    ci_size: usize,
    catch_table_offset: Option<usize>,
    catch_table_size: usize,
}

fn parse_body_header(
    bytes: &[u8],
    body_offset: usize,
    ci_layout_known: bool,
) -> Option<BodyHeader> {
    let mut pos: usize = body_offset;
    let mut iseq_size: usize = 0;
    let mut bytecode_offset: usize = 0;
    let mut bytecode_size: usize = 0;
    let mut param_lead_num: u32 = 0;
    let mut local_table_offset: Option<usize> = None;
    let mut local_table_size: usize = 0;
    let mut ci_entries_offset: Option<usize> = None;
    let mut ci_size: usize = 0;
    let mut catch_table_offset: Option<usize> = None;
    let mut catch_table_size: usize = 0;
    let reads: usize = if ci_layout_known {
        BODY_HEADER_READS
    } else {
        4
    };
    for read_idx in 0..reads {
        let (raw, next): (u64, usize) = read_small_value(bytes, pos)?;
        match read_idx {
            1 => iseq_size = usize::try_from(raw).ok()?.min(IBF_MAX_INSNS_PER_ISEQ),
            2 => {
                let rel: usize = usize::try_from(raw).ok()?;
                bytecode_offset = body_offset.checked_sub(rel)?;
            }
            3 => bytecode_size = usize::try_from(raw).ok()?,
            BODY_READ_PARAM_LEAD_NUM => {
                param_lead_num = u32::try_from(raw).unwrap_or(0).min(IBF_MAX_LOCALS as u32);
            }
            BODY_READ_LOCAL_TABLE_OFFSET => {
                let rel: usize = usize::try_from(raw).ok()?;
                local_table_offset = body_offset.checked_sub(rel);
            }
            BODY_READ_CATCH_TABLE_SIZE => {
                catch_table_size = usize::try_from(raw).ok()?.min(IBF_MAX_CATCH_ENTRIES);
            }
            BODY_READ_CATCH_TABLE_OFFSET => {
                let rel: usize = usize::try_from(raw).ok()?;
                catch_table_offset = body_offset.checked_sub(rel);
            }
            BODY_READ_CI_ENTRIES_OFFSET => {
                let rel: usize = usize::try_from(raw).ok()?;
                ci_entries_offset = body_offset.checked_sub(rel);
            }
            BODY_READ_LOCAL_TABLE_SIZE => {
                local_table_size = usize::try_from(raw).ok()?.min(IBF_MAX_LOCALS);
            }
            BODY_READ_CI_SIZE => ci_size = usize::try_from(raw).ok()?.min(IBF_MAX_CI_ENTRIES),
            _ => {}
        }
        pos = next;
    }
    Some(BodyHeader {
        iseq_size,
        bytecode_offset,
        bytecode_size,
        param_lead_num,
        local_table_offset,
        local_table_size,
        ci_entries_offset,
        ci_size,
        catch_table_offset,
        catch_table_size,
    })
}

/// Parse a body's `local_table`: a 4-byte-aligned `ID[local_table_size]` array (`ibf_dump_local_table`
fn parse_local_table(
    bytes: &[u8],
    objects: &ObjectTable<'_>,
    offset: usize,
    size: usize,
) -> Vec<Option<String>> {
    let aligned: usize = offset.div_ceil(4).saturating_mul(4);
    let mut names: Vec<Option<String>> = Vec::with_capacity(size.min(4096));
    for i in 0..size {
        let at: usize = match aligned.checked_add(i.wrapping_mul(4)) {
            Some(at) => at,
            None => break,
        };
        let Some(id_index): Option<u32> = read_u32_le(bytes, at) else {
            break;
        };
        names.push(objects.literal(u64::from(id_index)).map(str::to_owned));
    }
    names
}

fn parse_ci_entries(
    bytes: &[u8],
    objects: &ObjectTable<'_>,
    offset: usize,
    count: usize,
) -> Vec<CallEntry> {
    let mut entries: Vec<CallEntry> = Vec::with_capacity(count.min(4096));
    let mut pos: usize = offset;
    for _ in 0..count {
        let Some((mid_index, p1)): Option<(u64, usize)> = read_small_value(bytes, pos) else {
            break;
        };
        if mid_index == u64::MAX || (mid_index as i64) == -1 {
            entries.push(CallEntry {
                method: None,
                argc: 0,
            });
            pos = p1;
            continue;
        }
        let Some((_flag, p2)): Option<(u64, usize)> = read_small_value(bytes, p1) else {
            break;
        };
        let Some((argc, p3)): Option<(u64, usize)> = read_small_value(bytes, p2) else {
            break;
        };
        let Some((kwlen, p4)): Option<(u64, usize)> = read_small_value(bytes, p3) else {
            break;
        };
        let mut np: usize = p4;
        for _ in 0..kwlen.min(IBF_ARRAY_LEN_CAP as u64) {
            match read_small_value(bytes, np) {
                Some((_kw, n)) => np = n,
                None => break,
            }
        }
        entries.push(CallEntry {
            method: objects.literal(mid_index).map(str::to_owned),
            argc: u32::try_from(argc).unwrap_or(u32::MAX),
        });
        pos = np;
    }
    entries
}

/// Map an `INT2FIX(n)`-encoded catch type (`(n << 1) | 1`) to [`CatchType`].
const fn classify_catch_type(raw: u64) -> CatchType {
    match raw >> 1 {
        1 => CatchType::Rescue,
        2 => CatchType::Ensure,
        3 => CatchType::Retry,
        4 => CatchType::Break,
        5 => CatchType::Redo,
        6 => CatchType::Next,
        _ => CatchType::Unknown,
    }
}

/// Parse a body's `catch_table`: `count` entries of six `small_value`s each.
fn parse_catch_table(bytes: &[u8], offset: usize, count: usize) -> Vec<YarvCatchEntry> {
    let mut entries: Vec<YarvCatchEntry> = Vec::with_capacity(count.min(4096));
    let mut pos: usize = offset;
    for _ in 0..count {
        let Some((iseq_index, p1)): Option<(u64, usize)> = read_small_value(bytes, pos) else {
            break;
        };
        let Some((ty, p2)): Option<(u64, usize)> = read_small_value(bytes, p1) else {
            break;
        };
        let Some((start, p3)): Option<(u64, usize)> = read_small_value(bytes, p2) else {
            break;
        };
        let Some((end, p4)): Option<(u64, usize)> = read_small_value(bytes, p3) else {
            break;
        };
        let Some((cont, p5)): Option<(u64, usize)> = read_small_value(bytes, p4) else {
            break;
        };
        let Some((_sp, p6)): Option<(u64, usize)> = read_small_value(bytes, p5) else {
            break;
        };
        let handler_iseq: Option<u32> = (iseq_index != 0 && iseq_index != u64::MAX)
            .then(|| u32::try_from(iseq_index).unwrap_or(u32::MAX));
        entries.push(YarvCatchEntry {
            catch_type: classify_catch_type(ty),
            start_pc: u32::try_from(start).unwrap_or(u32::MAX),
            end_pc: u32::try_from(end).unwrap_or(u32::MAX),
            cont_pc: u32::try_from(cont).unwrap_or(u32::MAX),
            handler_iseq,
        });
        pos = p6;
    }
    entries
}

#[allow(clippy::too_many_lines)]
fn decode_iseq_body(
    bytes: &[u8],
    table: &[YarvOpcode],
    objects: &ObjectTable<'_>,
    body_offset: u32,
    index: u32,
    ci_layout_known: bool,
) -> Option<YarvIseqBody> {
    let start: usize = body_offset as usize;
    let header: BodyHeader = parse_body_header(bytes, start, ci_layout_known)?;

    let calls: Vec<CallEntry> = match header.ci_entries_offset {
        Some(ci_off) if ci_off <= bytes.len() && header.ci_size > 0 => {
            parse_ci_entries(bytes, objects, ci_off, header.ci_size)
        }
        _ => Vec::new(),
    };

    let local_table: Vec<Option<String>> = match header.local_table_offset {
        Some(lt_off) if lt_off <= bytes.len() && header.local_table_size > 0 => {
            parse_local_table(bytes, objects, lt_off, header.local_table_size)
        }
        _ => Vec::new(),
    };

    let catch_entries: Vec<YarvCatchEntry> = match header.catch_table_offset {
        Some(ct_off) if ct_off <= bytes.len() && header.catch_table_size > 0 => {
            parse_catch_table(bytes, ct_off, header.catch_table_size)
        }
        _ => Vec::new(),
    };

    let bytecode_end: usize = header
        .bytecode_offset
        .checked_add(header.bytecode_size)?
        .min(bytes.len());
    if header.bytecode_offset > bytes.len() {
        return Some(YarvIseqBody {
            index,
            offset: body_offset,
            iseq_size: u32::try_from(header.iseq_size).unwrap_or(u32::MAX),
            instructions: Vec::new(),
            local_table,
            param_lead_num: header.param_lead_num,
            catch_entries,
        });
    }

    let mut instructions: Vec<YarvIbfInstruction> = Vec::with_capacity(header.iseq_size.min(4096));
    let mut rp: usize = header.bytecode_offset;
    let mut decoded: usize = 0;
    let mut call_cursor: usize = 0;
    while rp < bytecode_end && decoded <= header.iseq_size {
        let insn_pc: usize = rp.saturating_sub(header.bytecode_offset);
        let (op, after_op): (u64, usize) = read_small_value(bytes, rp)?;
        rp = after_op;
        let op_idx: usize = usize::try_from(op).ok()?;
        let Some(spec): Option<&YarvOpcode> = table.get(op_idx) else {
            break;
        };
        let mut operands: Vec<YarvOperand> = Vec::with_capacity(spec.operands.len());
        for kind in spec.operands {
            let operand: YarvOperand = match kind {
                TsKind::CallData => {
                    let entry: Option<&CallEntry> = calls.get(call_cursor);
                    call_cursor += 1;
                    match entry {
                        Some(CallEntry {
                            method: Some(name),
                            argc,
                        }) => YarvOperand::Call {
                            method: name.clone(),
                            argc: *argc,
                        },
                        Some(CallEntry { method: None, argc }) => YarvOperand::Call {
                            method: "(call)".to_owned(),
                            argc: *argc,
                        },
                        None => YarvOperand::Num(0),
                    }
                }
                TsKind::Builtin => {
                    let (bidx, p1): (u64, usize) = read_small_value(bytes, rp)?;
                    let (blen, p2): (u64, usize) = read_small_value(bytes, p1)?;
                    let blen_usize: usize =
                        usize::try_from(blen).unwrap_or(0).min(IBF_STRING_LEN_CAP);
                    let name_end: usize = p2.saturating_add(blen_usize);
                    let name: String = bytes.get(p2..name_end).map_or_else(
                        || format!("builtin#{bidx}"),
                        |s| String::from_utf8_lossy(s).into_owned(),
                    );
                    rp = name_end;
                    YarvOperand::Builtin(name)
                }
                TsKind::Variable => break,
                _ => {
                    let (raw, next): (u64, usize) = read_small_value(bytes, rp)?;
                    rp = next;
                    resolve_operand(*kind, raw, objects)
                }
            };
            operands.push(operand);
        }
        instructions.push(YarvIbfInstruction {
            pc: u32::try_from(insn_pc).unwrap_or(u32::MAX),
            opcode: op_idx as u32,
            mnemonic: spec.mnemonic.to_owned(),
            operands,
        });
        decoded += 1 + spec.operands.len();
    }

    Some(YarvIseqBody {
        index,
        offset: body_offset,
        iseq_size: u32::try_from(header.iseq_size).unwrap_or(u32::MAX),
        instructions,
        local_table,
        param_lead_num: header.param_lead_num,
        catch_entries,
    })
}

fn resolve_operand(kind: TsKind, raw: u64, objects: &ObjectTable<'_>) -> YarvOperand {
    let ref_index: u32 = u32::try_from(raw).unwrap_or(u32::MAX);
    match kind {
        TsKind::Value | TsKind::CdHash | TsKind::Ic => objects.typed_literal(raw).map_or_else(
            || YarvOperand::ObjectRef(ref_index),
            |(lit, numeric)| {
                if numeric {
                    YarvOperand::NumLiteral(lit.to_owned())
                } else {
                    YarvOperand::Literal(lit.to_owned())
                }
            },
        ),
        TsKind::Id => objects.literal(raw).map_or_else(
            || YarvOperand::ObjectRef(ref_index),
            |name| YarvOperand::Id(name.to_owned()),
        ),
        TsKind::Iseq => YarvOperand::IseqRef(ref_index),
        TsKind::Offset => YarvOperand::Offset(raw as u32),
        _ => YarvOperand::Num(raw),
    }
}

pub(crate) fn parse_image(
    bytes: &[u8],
    header: &YarvBinaryHeader,
    version: YarvVersion,
) -> IbfImage {
    let total: usize = bytes.len();
    let table_cap: usize = total / 4;
    let iseq_n: usize =
        (header.iseq_list_size.min(IBF_OBJECT_LIST_ENTRY_CAP) as usize).min(table_cap);
    let obj_n: usize = (header
        .global_object_list_size
        .min(IBF_OBJECT_LIST_ENTRY_CAP) as usize)
        .min(table_cap);

    let iseq_base: usize = header.iseq_list_offset as usize;
    let mut iseq_offsets: Vec<u32> = Vec::with_capacity(iseq_n);
    for i in 0..iseq_n {
        let at: usize = match iseq_base.checked_add(i.wrapping_mul(4)) {
            Some(at) => at,
            None => break,
        };
        let Some(v): Option<u32> = read_u32_le(bytes, at) else {
            break;
        };
        iseq_offsets.push(v);
    }

    let obj_base: usize = header.global_object_list_offset as usize;
    let mut objects: Vec<IbfObject> = Vec::with_capacity(obj_n);
    let mut recovered_literal_count: u32 = 0;
    for i in 0..obj_n {
        let at: usize = match obj_base.checked_add(i.wrapping_mul(4)) {
            Some(at) => at,
            None => break,
        };
        let Some(obj_off): Option<u32> = read_u32_le(bytes, at) else {
            break;
        };
        let index: u32 = u32::try_from(i).unwrap_or(u32::MAX);
        if (obj_off as usize) >= total {
            objects.push(IbfObject {
                index,
                offset: obj_off,
                kind: IbfObjectKind::Unknown,
                literal: None,
                element_count: None,
                elements: Vec::new(),
            });
            continue;
        }
        let obj: IbfObject = decode_object(bytes, index, obj_off);
        if obj.literal.is_some() {
            recovered_literal_count += 1;
        }
        objects.push(obj);
    }

    resolve_regexp_literals(&mut objects, &mut recovered_literal_count);

    let mut iseqs: Vec<YarvIseqBody> = Vec::new();
    let mut recovered_instruction_count: u32 = 0;
    if let Some(table) = version.opcode_table() {
        let ci_layout_known: bool = version.major == 3 && version.minor >= 3;
        let obj_table: ObjectTable<'_> = ObjectTable { objects: &objects };
        let limit: usize = iseq_offsets.len().min(IBF_MAX_ISEQ_BODIES);
        for (i, &body_off) in iseq_offsets.iter().take(limit).enumerate() {
            if (body_off as usize) >= total {
                continue;
            }
            let index: u32 = u32::try_from(i).unwrap_or(u32::MAX);
            if let Some(body) =
                decode_iseq_body(bytes, table, &obj_table, body_off, index, ci_layout_known)
            {
                recovered_instruction_count = recovered_instruction_count
                    .saturating_add(u32::try_from(body.instructions.len()).unwrap_or(u32::MAX));
                iseqs.push(body);
            }
        }
    }

    IbfImage {
        iseq_offsets,
        objects,
        iseqs,
        recovered_literal_count,
        recovered_instruction_count,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn small_value_single_byte_odd_flag() {
        let bytes: [u8; 1] = [0x17];
        let (v, next): (u64, usize) = read_small_value(&bytes, 0).expect("decode");
        assert_eq!(v, 11);
        assert_eq!(next, 1);
    }

    #[test]
    fn small_value_two_byte_continuation() {
        let bytes: [u8; 2] = [0x02, 0x40];
        let (v, next): (u64, usize) = read_small_value(&bytes, 0).expect("decode");
        assert_eq!(v, 0x40);
        assert_eq!(next, 2);
    }

    #[test]
    fn local_table_resolves_object_indices_to_symbol_names() {
        let objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Nil,
                literal: None,
                element_count: None,
                elements: Vec::new(),
            },
            IbfObject {
                index: 1,
                offset: 0,
                kind: IbfObjectKind::Symbol,
                literal: Some("count".to_owned()),
                element_count: None,
                elements: Vec::new(),
            },
            IbfObject {
                index: 2,
                offset: 0,
                kind: IbfObjectKind::Symbol,
                literal: Some("name".to_owned()),
                element_count: None,
                elements: Vec::new(),
            },
        ];
        let table: ObjectTable<'_> = ObjectTable { objects: &objects };
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        let names: Vec<Option<String>> = parse_local_table(&bytes, &table, 0, 2);
        assert_eq!(
            names,
            vec![Some("name".to_owned()), Some("count".to_owned())]
        );
    }

    #[test]
    fn local_table_hidden_slot_is_none() {
        let objects: Vec<IbfObject> = vec![IbfObject {
            index: 0,
            offset: 0,
            kind: IbfObjectKind::Fixnum,
            literal: None,
            element_count: None,
            elements: Vec::new(),
        }];
        let table: ObjectTable<'_> = ObjectTable { objects: &objects };
        let bytes: [u8; 4] = 0u32.to_le_bytes();
        let names: Vec<Option<String>> = parse_local_table(&bytes, &table, 0, 1);
        assert_eq!(names, vec![None]);
    }

    #[test]
    fn catch_table_decodes_rescue_entry() {
        let int2fix_rescue: u64 = (1 << 1) | 1;
        let fields: [u64; 6] = [2, int2fix_rescue, 0, 6, 7, 0];
        let mut bytes: Vec<u8> = Vec::new();
        for f in fields {
            bytes.extend_from_slice(&dump_small_value(f));
        }
        let entries: Vec<YarvCatchEntry> = parse_catch_table(&bytes, 0, 1);
        assert_eq!(entries.len(), 1);
        let entry: &YarvCatchEntry = &entries[0];
        assert_eq!(entry.catch_type, CatchType::Rescue);
        assert_eq!(entry.start_pc, 0);
        assert_eq!(entry.end_pc, 6);
        assert_eq!(entry.cont_pc, 7);
        assert_eq!(entry.handler_iseq, Some(2));
    }

    #[test]
    fn regexp_escapes_inner_slashes() {
        assert_eq!(escape_regexp_slashes("^/api/v"), "^\\/api\\/v");
        assert_eq!(escape_regexp_slashes("a\\/b"), "a\\/b");
        assert_eq!(escape_regexp_slashes("plain"), "plain");
    }

    #[test]
    fn regexp_literal_resolves_from_source_string() {
        let mut objects: Vec<IbfObject> = vec![
            IbfObject {
                index: 0,
                offset: 0,
                kind: IbfObjectKind::Regexp,
                literal: None,
                element_count: None,
                elements: vec![1],
            },
            IbfObject {
                index: 1,
                offset: 0,
                kind: IbfObjectKind::String,
                literal: Some("\\Aregex".to_owned()),
                element_count: None,
                elements: Vec::new(),
            },
        ];
        let mut recovered: u32 = 0;
        resolve_regexp_literals(&mut objects, &mut recovered);
        assert_eq!(objects[0].literal.as_deref(), Some("/\\Aregex/"));
        assert_eq!(recovered, 1);
    }

    #[test]
    fn fixnum_object_decodes_to_numeric_literal() {
        let mut bytes: Vec<u8> = vec![0x00; 4];
        bytes.push(0x35);
        bytes.extend_from_slice(&dump_small_value((2 << 1) | 1));
        let obj: IbfObject = decode_object(&bytes, 0, 4);
        assert_eq!(obj.kind, IbfObjectKind::Fixnum);
        assert_eq!(obj.literal.as_deref(), Some("2"));
    }

    #[test]
    fn catch_table_null_handler_is_none() {
        let int2fix_retry: u64 = (3 << 1) | 1;
        let fields: [u64; 6] = [0, int2fix_retry, 6, 7, 0, 0];
        let mut bytes: Vec<u8> = Vec::new();
        for f in fields {
            bytes.extend_from_slice(&dump_small_value(f));
        }
        let entries: Vec<YarvCatchEntry> = parse_catch_table(&bytes, 0, 1);
        assert_eq!(entries[0].catch_type, CatchType::Retry);
        assert_eq!(entries[0].handler_iseq, None);
    }

    #[test]
    fn small_value_roundtrip_against_dump_formula() {
        for value in [0u64, 1, 63, 64, 127, 128, 16_383, 16_384, 1_000_000] {
            let encoded: Vec<u8> = dump_small_value(value);
            let (decoded, used): (u64, usize) =
                read_small_value(&encoded, 0).expect("decode roundtrip");
            assert_eq!(decoded, value, "value {value}");
            assert_eq!(used, encoded.len(), "length {value}");
        }
    }

    #[test]
    fn small_value_rejects_truncated_continuation() {
        let bytes: [u8; 1] = [0x02];
        assert!(read_small_value(&bytes, 0).is_none());
    }

    #[test]
    fn decode_string_object_recovers_literal() {
        let mut bytes: Vec<u8> = vec![0x00; 4];
        bytes.push(0x45);
        bytes.push(0x03);
        bytes.push(0x17);
        bytes.extend_from_slice(b"hello world");
        let obj: IbfObject = decode_object(&bytes, 0, 4);
        assert_eq!(obj.kind, IbfObjectKind::String);
        assert_eq!(obj.literal.as_deref(), Some("hello world"));
    }

    #[test]
    fn out_of_bounds_string_len_is_safe() {
        let bytes: Vec<u8> = vec![
            0x45, 0x03, 0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let obj: IbfObject = decode_object(&bytes, 0, 0);
        assert!(obj.literal.is_none());
    }

    fn dump_small_value(mut x: u64) -> Vec<u8> {
        let max_len: usize = 9;
        let mut bytes: Vec<u8> = vec![0u8; max_len];
        let mut n: u32 = 0;
        while (n as usize) < 8 && (x >> (7 - n)) != 0 {
            bytes[max_len - 1 - n as usize] = x as u8;
            n += 1;
            x >>= 8;
        }
        x <<= 1;
        x |= 1;
        x <<= n;
        bytes[max_len - 1 - n as usize] = x as u8;
        n += 1;
        bytes.split_off(max_len - n as usize)
    }
}
