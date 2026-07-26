#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;

use disrobe_nir::{NirModule, NirOp};
use disrobe_nir_lift::{LiftError, lift_abc, lift_swf_abc};
use disrobe_pass_as3::abc::{self, AbcFile, DisasmLine, MethodBody};
use disrobe_query::{CallSiteMatch, FunctionMatch, Module, Query, QueryResult, XrefMatch, run};

const ABC_MINOR: u16 = 16;
const ABC_MAJOR: u16 = 46;

fn u30(mut value: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        let mut byte: u8 = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

const fn s24(value: i32) -> [u8; 3] {
    let raw: u32 = (value as u32) & 0x00FF_FFFF;
    [
        (raw & 0xFF) as u8,
        ((raw >> 8) & 0xFF) as u8,
        ((raw >> 16) & 0xFF) as u8,
    ]
}

struct Pool {
    strings: Vec<String>,
    namespaces: Vec<(u8, u32)>,
    multinames: Vec<(u32, u32)>,
}

impl Pool {
    fn new() -> Self {
        Self {
            strings: vec![String::new()],
            namespaces: vec![(0, 0)],
            multinames: vec![(0, 0)],
        }
    }

    fn intern_string(&mut self, s: &str) -> u32 {
        if let Some(pos) = self.strings.iter().position(|x: &String| x == s) {
            return pos as u32;
        }
        self.strings.push(s.to_owned());
        (self.strings.len() - 1) as u32
    }

    fn intern_ns(&mut self, kind: u8, name: &str) -> u32 {
        let name_idx: u32 = self.intern_string(name);
        self.namespaces.push((kind, name_idx));
        (self.namespaces.len() - 1) as u32
    }

    fn intern_qname(&mut self, ns: u32, name: &str) -> u32 {
        let name_idx: u32 = self.intern_string(name);
        self.multinames.push((ns, name_idx));
        (self.multinames.len() - 1) as u32
    }

    fn emit(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend(u30(1));
        out.extend(u30(1));
        out.extend(u30(1));
        out.extend(u30(self.strings.len() as u32));
        for s in &self.strings[1..] {
            let raw: &[u8] = s.as_bytes();
            out.extend(u30(raw.len() as u32));
            out.extend_from_slice(raw);
        }
        out.extend(u30(self.namespaces.len() as u32));
        for (kind, name_idx) in &self.namespaces[1..] {
            out.push(*kind);
            out.extend(u30(*name_idx));
        }
        out.extend(u30(1));
        out.extend(u30(self.multinames.len() as u32));
        for (ns, name) in &self.multinames[1..] {
            out.push(0x07);
            out.extend(u30(*ns));
            out.extend(u30(*name));
        }
        out
    }
}

fn emit_method_info(param_types: &[u32], return_type: u32, name: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend(u30(param_types.len() as u32));
    out.extend(u30(return_type));
    for p in param_types {
        out.extend(u30(*p));
    }
    out.extend(u30(name));
    out.push(0x00);
    out
}

fn emit_body(method: u32, max_stack: u32, local_count: u32, code: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend(u30(method));
    out.extend(u30(max_stack));
    out.extend(u30(local_count));
    out.extend(u30(1));
    out.extend(u30(max_stack.max(1)));
    out.extend(u30(code.len() as u32));
    out.extend_from_slice(code);
    out.extend(u30(0));
    out.extend(u30(0));
    out
}

const PKG: u8 = 0x16;

#[derive(Clone, Copy)]
enum GreetBody {
    Absent,
    Empty,
    Full,
    InvalidOwner,
    InvalidSwitch,
    InvalidExplicitLocal,
    InvalidImplicitLocal,
    InvalidLocalPair,
    InvalidLocalArithmetic,
}

fn build_abc_with_greet_body(greet_body: GreetBody) -> Vec<u8> {
    let mut pool: Pool = Pool::new();
    let pkg_ns: u32 = pool.intern_ns(PKG, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Greeter");
    let object_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let greet_mn: u32 = pool.intern_qname(pkg_ns, "greet");
    let trace_mn: u32 = pool.intern_qname(pkg_ns, "trace");
    let label_mn: u32 = pool.intern_qname(pkg_ns, "label");
    let push_mn: u32 = pool.intern_qname(pkg_ns, "push");
    let hello_str: u32 = pool.intern_string("hello world");
    let banner_str: u32 = pool.intern_string("banner");

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD0);
    code.push(0x30);

    code.push(0x5D);
    code.extend(u30(trace_mn));
    code.push(0x2C);
    code.extend(u30(hello_str));
    code.push(0x4F);
    code.extend(u30(trace_mn));
    code.extend(u30(1));

    code.push(0xD0);
    code.push(0x2C);
    code.extend(u30(banner_str));
    code.push(0x61);
    code.extend(u30(label_mn));

    code.push(0xD0);
    code.push(0x66);
    code.extend(u30(label_mn));
    code.push(0x12);
    let iffalse_at: usize = code.len();
    code.extend_from_slice(&s24(0));
    let after_iffalse: usize = code.len();

    code.push(0xD1);
    code.push(0x4F);
    code.extend(u30(push_mn));
    code.extend(u30(1));

    let jump_target: usize = code.len();
    code.push(0x10);
    let jump_at: usize = code.len();
    code.extend_from_slice(&s24(0));
    let after_jump: usize = code.len();

    let return_off: usize = code.len();
    code.push(0x47);

    let patch: fn(&mut Vec<u8>, usize, usize, usize) =
        |code: &mut Vec<u8>, at: usize, after: usize, target: usize| {
            let rel: i32 = target as i32 - after as i32;
            let bytes: [u8; 3] = s24(rel);
            code[at] = bytes[0];
            code[at + 1] = bytes[1];
            code[at + 2] = bytes[2];
        };
    patch(&mut code, iffalse_at, after_iffalse, return_off);
    patch(&mut code, jump_at, after_jump, jump_target);

    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&ABC_MINOR.to_le_bytes());
    b.extend_from_slice(&ABC_MAJOR.to_le_bytes());
    b.extend(pool.emit());

    b.extend(u30(2));
    b.extend(emit_method_info(&[], 0, 0));
    b.extend(emit_method_info(&[object_mn], 0, greet_mn));

    b.extend(u30(0));

    b.extend(u30(1));
    b.extend(u30(class_mn));
    b.extend(u30(object_mn));
    b.push(0x00);
    b.extend(u30(0));
    b.extend(u30(0));
    b.extend(u30(1));
    b.extend(u30(greet_mn));
    b.push(0x01);
    b.extend(u30(0));
    b.extend(u30(1));

    b.extend(u30(0));
    b.extend(u30(0));

    b.extend(u30(1));
    b.extend(u30(0));
    b.extend(u30(0));

    let body_count: u32 = if matches!(greet_body, GreetBody::Absent) {
        1
    } else {
        2
    };
    b.extend(u30(body_count));
    b.extend(emit_body(0, 1, 1, &[0x47]));
    match greet_body {
        GreetBody::Absent => {}
        GreetBody::Empty => b.extend(emit_body(1, 4, 2, &[])),
        GreetBody::Full => b.extend(emit_body(1, 4, 2, &code)),
        GreetBody::InvalidOwner => b.extend(emit_body(127, 4, 2, &code)),
        GreetBody::InvalidSwitch => {
            b.extend(emit_body(
                1,
                4,
                2,
                &[0x1B, 0x7F, 0x00, 0x00, 0x00, 0x7F, 0x00, 0x00],
            ));
        }
        GreetBody::InvalidExplicitLocal => {
            b.extend(emit_body(1, 1, 2, &[0x62, 0x02, 0x47]));
        }
        GreetBody::InvalidImplicitLocal => {
            b.extend(emit_body(1, 1, 2, &[0xD3, 0x47]));
        }
        GreetBody::InvalidLocalPair => {
            b.extend(emit_body(1, 1, 2, &[0x32, 0x00, 0x02, 0x47]));
        }
        GreetBody::InvalidLocalArithmetic => {
            b.extend(emit_body(1, 1, 2, &[0x92, 0x02, 0x47]));
        }
    }
    b
}

fn build_abc() -> Vec<u8> {
    build_abc_with_greet_body(GreetBody::Full)
}

fn push_swf_tag(body: &mut Vec<u8>, tag_code: u16, payload: &[u8]) {
    let payload_len: u32 = u32::try_from(payload.len()).expect("SWF tag payload length");
    let short_len: u16 = if payload_len < 0x3F {
        payload_len as u16
    } else {
        0x3F
    };
    let header: u16 = (tag_code << 6) | short_len;
    body.extend_from_slice(&header.to_le_bytes());
    if short_len == 0x3F {
        body.extend_from_slice(&payload_len.to_le_bytes());
    }
    body.extend_from_slice(payload);
}

fn build_swf(abc_bytes: &[u8]) -> Vec<u8> {
    let mut do_abc: Vec<u8> = Vec::with_capacity(abc_bytes.len().saturating_add(8));
    do_abc.extend_from_slice(&1_u32.to_le_bytes());
    do_abc.extend_from_slice(b"NirTest\0");
    do_abc.extend_from_slice(abc_bytes);

    let mut body: Vec<u8> = vec![0x00];
    body.extend_from_slice(&24_u16.to_le_bytes());
    body.extend_from_slice(&1_u16.to_le_bytes());
    push_swf_tag(&mut body, 69, &[0x08, 0x00, 0x00, 0x00]);
    push_swf_tag(&mut body, 82, &do_abc);
    push_swf_tag(&mut body, 0, &[]);

    let file_len: u32 =
        u32::try_from(body.len().saturating_add(8)).expect("synthetic SWF file length");
    let capacity: usize = usize::try_from(file_len).expect("synthetic SWF capacity");
    let mut swf: Vec<u8> = Vec::with_capacity(capacity);
    swf.extend_from_slice(b"FWS");
    swf.push(13);
    swf.extend_from_slice(&file_len.to_le_bytes());
    swf.extend_from_slice(&body);
    swf
}

fn abc_with_malformed_method_body() -> Vec<u8> {
    let mut bytes: Vec<u8> = build_abc();
    let opcode_offset: usize = bytes.len().saturating_sub(3);
    bytes[opcode_offset] = 0x24;
    bytes
}

fn abc_with_unknown_opcode() -> Vec<u8> {
    let mut bytes: Vec<u8> = build_abc();
    let opcode_offset: usize = bytes.len().saturating_sub(3);
    bytes[opcode_offset] = 0x00;
    bytes
}

fn abc_with_invalid_pool_reference() -> Vec<u8> {
    let mut bytes: Vec<u8> = build_abc();
    let parsed: AbcFile = abc::parse(&bytes).expect("parse ABC container");
    let body: &MethodBody = parsed.method_bodies.last().expect("method body");
    let lines: Vec<DisasmLine> = abc::disasm(&body.code).expect("disassemble body");
    let pushstring: &DisasmLine = lines
        .iter()
        .find(|line: &&DisasmLine| line.opcode == 0x2C)
        .expect("pushstring");
    let code_start: usize = bytes.len() - 2 - body.code.len();
    bytes[code_start + pushstring.offset + 1] = 0x7F;
    bytes
}

fn lifted_nir() -> NirModule {
    lift_abc(&build_abc()).expect("lift ABC to NIR")
}

#[test]
fn malformed_avm2_body_refuses_the_lift() {
    let bytes: Vec<u8> = abc_with_malformed_method_body();
    let parsed: AbcFile = abc::parse(&bytes).expect("parse ABC container");
    let body: &MethodBody = parsed.method_bodies.last().expect("method body");
    assert!(abc::disasm(&body.code).is_err());

    let lifted: disrobe_nir_lift::Result<NirModule> = lift_abc(&bytes);
    assert!(
        matches!(
            lifted,
            Err(LiftError::Source(message))
                if message.contains("avm2") && message.contains("disassembl")
        ),
        "malformed AVM2 body must not become a recovered empty function"
    );
}

#[test]
fn unknown_avm2_opcode_refuses_the_lift() {
    let bytes: Vec<u8> = abc_with_unknown_opcode();
    let parsed: AbcFile = abc::parse(&bytes).expect("parse ABC container");
    let body: &MethodBody = parsed.method_bodies.last().expect("method body");
    let decoded: Vec<disrobe_pass_as3::abc::DisasmLine> =
        abc::disasm(&body.code).expect("decoder exposes unknown opcode");
    assert!(
        decoded
            .iter()
            .any(|line: &disrobe_pass_as3::abc::DisasmLine| line.mnemonic == "<unknown>")
    );

    let lifted: disrobe_nir_lift::Result<NirModule> = lift_abc(&bytes);
    assert!(
        matches!(
            lifted,
            Err(LiftError::Source(message))
                if message.contains("avm2") && message.contains("unknown opcode")
        ),
        "an unknown AVM2 opcode must not become a recovered instruction"
    );
}

#[test]
fn absent_and_decoded_empty_avm2_bodies_are_distinct() {
    let absent: NirModule =
        lift_abc(&build_abc_with_greet_body(GreetBody::Absent)).expect("absent body");
    assert!(
        absent
            .functions
            .iter()
            .all(|function| function.name != "greet")
    );

    let empty: NirModule =
        lift_abc(&build_abc_with_greet_body(GreetBody::Empty)).expect("empty body");
    let greet: &disrobe_nir::NirFunction = empty
        .functions
        .iter()
        .find(|function| function.name == "greet")
        .expect("empty body function");
    assert!(greet.instructions.is_empty());
}

#[test]
fn invalid_avm2_owner_and_pool_references_refuse_the_lift() {
    let invalid_owner: disrobe_nir_lift::Result<NirModule> =
        lift_abc(&build_abc_with_greet_body(GreetBody::InvalidOwner));
    assert!(matches!(invalid_owner, Err(LiftError::Source(_))));

    let invalid_pool: disrobe_nir_lift::Result<NirModule> =
        lift_abc(&abc_with_invalid_pool_reference());
    assert!(matches!(invalid_pool, Err(LiftError::Source(_))));
}

#[test]
fn invalid_avm2_branch_and_switch_targets_refuse_the_lift() {
    let mut branch_bytes: Vec<u8> = build_abc();
    let parsed: AbcFile = abc::parse(&branch_bytes).expect("parse ABC container");
    let body: &MethodBody = parsed.method_bodies.last().expect("method body");
    let lines: Vec<DisasmLine> = abc::disasm(&body.code).expect("disassemble body");
    let branch: &DisasmLine = lines
        .iter()
        .find(|line: &&DisasmLine| line.opcode == 0x12)
        .expect("conditional branch");
    let code_start: usize = branch_bytes.len() - 2 - body.code.len();
    branch_bytes[code_start + branch.offset + 1..code_start + branch.offset + 4]
        .copy_from_slice(&s24(0x7F_FFFF));
    let invalid_branch: disrobe_nir_lift::Result<NirModule> = lift_abc(&branch_bytes);
    assert!(matches!(invalid_branch, Err(LiftError::Source(_))));

    let invalid_switch: disrobe_nir_lift::Result<NirModule> =
        lift_abc(&build_abc_with_greet_body(GreetBody::InvalidSwitch));
    assert!(matches!(invalid_switch, Err(LiftError::Source(_))));
}

#[test]
fn invalid_avm2_local_registers_refuse_the_lift() {
    let cases: [GreetBody; 4] = [
        GreetBody::InvalidExplicitLocal,
        GreetBody::InvalidImplicitLocal,
        GreetBody::InvalidLocalPair,
        GreetBody::InvalidLocalArithmetic,
    ];
    for body in cases {
        let lifted: disrobe_nir_lift::Result<NirModule> =
            lift_abc(&build_abc_with_greet_body(body));
        assert!(matches!(lifted, Err(LiftError::Source(_))));
    }
}

struct OracleFacts {
    callees: BTreeSet<String>,
    pushstrings: BTreeSet<String>,
    property_accesses: BTreeSet<String>,
    branch_edges: usize,
}

fn independent_oracle() -> OracleFacts {
    let abc: AbcFile = abc::parse(&build_abc()).expect("oracle abc parse");
    let mut callees: BTreeSet<String> = BTreeSet::new();
    let mut pushstrings: BTreeSet<String> = BTreeSet::new();
    let mut property_accesses: BTreeSet<String> = BTreeSet::new();
    let mut branch_edges: usize = 0;

    for body in &abc.method_bodies {
        let body: &MethodBody = body;
        let lines: Vec<DisasmLine> = abc::disasm(&body.code).expect("oracle disasm");
        for line in &lines {
            match line.opcode {
                0x46 | 0x4F | 0x4C | 0x4A | 0x45 | 0x4E => {
                    if let Some(idx) = line
                        .operands
                        .first()
                        .and_then(|v: &i64| u32::try_from(*v).ok())
                    {
                        callees.insert(
                            abc.cpool
                                .render_multiname_property(idx)
                                .unwrap_or_else(|_| String::with_capacity(0)),
                        );
                    }
                }
                0x2C => {
                    if let Some(idx) = line
                        .operands
                        .first()
                        .and_then(|v: &i64| u32::try_from(*v).ok())
                    {
                        pushstrings.insert(
                            abc.cpool
                                .string_at(idx)
                                .map_or("", |value: &str| value)
                                .to_owned(),
                        );
                    }
                }
                0x61 | 0x66 | 0x68 => {
                    if let Some(idx) = line
                        .operands
                        .first()
                        .and_then(|v: &i64| u32::try_from(*v).ok())
                    {
                        property_accesses.insert(
                            abc.cpool
                                .render_multiname_property(idx)
                                .unwrap_or_else(|_| String::with_capacity(0)),
                        );
                    }
                }
                0x0C..=0x1B => {
                    branch_edges += 1;
                }
                _ => {}
            }
        }
    }

    OracleFacts {
        callees,
        pushstrings,
        property_accesses,
        branch_edges,
    }
}

fn lifted_callees(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Call { .. } | NirOp::IndirectCall)
                && matches!(
                    ins.mnemonic.as_str(),
                    "callpropvoid"
                        | "callproperty"
                        | "callproplex"
                        | "constructprop"
                        | "callsuper"
                        | "callsupervoid"
                )
                && let Some(name) = ins.operands.first()
            {
                out.insert(name.clone());
            }
        }
    }
    out
}

fn lifted_pushstrings(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if ins.op == NirOp::Const
                && ins.mnemonic == "pushstring"
                && let Some(v) = ins.operands.first()
            {
                out.insert(v.clone());
            }
        }
    }
    out
}

fn lifted_property_accesses(nir: &NirModule) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::new();
    for f in &nir.functions {
        for ins in &f.instructions {
            if matches!(ins.op, NirOp::Load | NirOp::Store)
                && matches!(
                    ins.mnemonic.as_str(),
                    "getproperty" | "setproperty" | "initproperty"
                )
                && let Some(name) = ins.operands.first()
            {
                out.insert(name.clone());
            }
        }
    }
    out
}

fn lifted_branch_edges(nir: &NirModule) -> usize {
    nir.functions
        .iter()
        .flat_map(|f| f.instructions.iter())
        .filter(|ins| matches!(ins.op, NirOp::Branch { .. } | NirOp::CondBranch { .. }))
        .count()
}

fn lifted_module() -> Module {
    Module::from_nir(&lifted_nir())
}

fn function_names(module: &Module) -> Vec<String> {
    match run(module, &Query::Functions) {
        QueryResult::Functions { matches } => {
            matches.into_iter().map(|m: FunctionMatch| m.name).collect()
        }
        other => panic!("expected Functions, got {other:?}"),
    }
}

#[test]
fn methods_are_recovered_as_named_functions() {
    let module: Module = lifted_module();
    let names: Vec<String> = function_names(&module);
    assert!(
        names.iter().any(|n: &String| n == "greet"),
        "the greet method must lift to a named function: {names:?}"
    );
}

#[test]
fn lifted_callees_match_the_independent_abc_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    let lifted: BTreeSet<String> = lifted_callees(&nir);
    assert!(
        !oracle.callees.is_empty(),
        "the source body issues callpropvoid sites"
    );
    assert_eq!(
        lifted, oracle.callees,
        "lifted Mir call targets must equal the ABC's actual callproperty set"
    );
    assert!(
        oracle.callees.contains("trace") && oracle.callees.contains("push"),
        "source calls trace and push: {:?}",
        oracle.callees
    );
}

#[test]
fn lifted_pushstrings_match_the_independent_abc_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    let lifted: BTreeSet<String> = lifted_pushstrings(&nir);
    assert_eq!(
        lifted, oracle.pushstrings,
        "lifted pushstring literals must equal the ABC's actual string constant set"
    );
    for literal in ["hello world", "banner"] {
        assert!(
            oracle.pushstrings.iter().any(|s: &String| s == literal),
            "source pushes {literal:?}: {:?}",
            oracle.pushstrings
        );
    }
}

#[test]
fn lifted_property_accesses_match_the_independent_abc_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    let lifted: BTreeSet<String> = lifted_property_accesses(&nir);
    assert_eq!(
        lifted, oracle.property_accesses,
        "lifted property-access multinames must equal the ABC's actual get/set property set"
    );
    assert!(
        oracle.property_accesses.contains("label"),
        "source reads and writes label: {:?}",
        oracle.property_accesses
    );
}

#[test]
fn lifted_branch_edge_count_matches_the_independent_abc_decode() {
    let oracle: OracleFacts = independent_oracle();
    let nir: NirModule = lifted_nir();
    assert!(oracle.branch_edges >= 2, "source has an iffalse and a jump");
    assert_eq!(
        lifted_branch_edges(&nir),
        oracle.branch_edges,
        "lifted Mir branch/cond-branch count must equal the ABC's actual branch instruction count"
    );
}

#[test]
fn conditional_branch_target_is_resolved_to_an_absolute_address() {
    let nir: NirModule = lifted_nir();
    let greet: &disrobe_nir::NirFunction = nir
        .functions
        .iter()
        .find(|f| f.name == "greet")
        .expect("greet");
    let cond: &disrobe_nir::NirInstr = greet
        .instructions
        .iter()
        .find(|ins| ins.mnemonic == "iffalse")
        .expect("iffalse present");
    let NirOp::CondBranch { target } = cond.op else {
        panic!("iffalse must lift to CondBranch: {:?}", cond.op);
    };
    let target: u64 = target.expect("iffalse target must resolve to an absolute address");
    assert!(
        greet.instructions.iter().any(|ins| ins.address == target),
        "the resolved branch target must land on a real lifted instruction"
    );
}

#[test]
fn calls_to_trace_resolve_through_a_call_edge() {
    let module: Module = lifted_module();
    let call_sites: Vec<CallSiteMatch> = match run(
        &module,
        &Query::CallsTo {
            target: "trace".to_owned(),
        },
    ) {
        QueryResult::CallsTo { matches, .. } => matches,
        other => panic!("expected CallsTo, got {other:?}"),
    };
    assert!(
        !call_sites.is_empty(),
        "the trace callpropvoid must surface as a resolved call site"
    );
    let xrefs: Vec<XrefMatch> = match run(
        &module,
        &Query::XrefsTo {
            symbol: "trace".to_owned(),
        },
    ) {
        QueryResult::XrefsTo { matches, .. } => matches,
        other => panic!("expected XrefsTo, got {other:?}"),
    };
    assert!(
        xrefs
            .iter()
            .filter_map(|x: &XrefMatch| x.from_function.as_deref())
            .any(|c: &str| c == "greet"),
        "greet must reference trace: {xrefs:?}"
    );
}

#[test]
fn swf_entry_routes_through_the_avm2_lifter() {
    let bytes: Vec<u8> = build_swf(&build_abc());
    let nir: NirModule = lift_swf_abc(&bytes).expect("lift the synthetic Greeter SWF");
    assert_eq!(nir.lang, disrobe_nir::SourceLang::Avm2);
    assert!(
        nir.functions.iter().any(|f| f.name == "greet"),
        "the SWF DoABC greet method must lift: {:?}",
        nir.functions
            .iter()
            .map(|f| f.name.as_str())
            .collect::<Vec<&str>>()
    );
    let branches: usize = nir
        .functions
        .iter()
        .flat_map(|f| f.instructions.iter())
        .filter(|ins| matches!(ins.op, NirOp::Branch { .. } | NirOp::CondBranch { .. }))
        .count();
    assert!(
        branches >= 2,
        "the greet body has a conditional and an unconditional branch"
    );
}

#[test]
fn committed_swf_with_out_of_range_local_is_refused() {
    let bytes: Vec<u8> =
        std::fs::read(swf_fixture_path()).expect("read committed synthetic Counter SWF");
    let lifted: disrobe_nir_lift::Result<NirModule> = lift_swf_abc(&bytes);
    assert!(
        matches!(
            lifted,
            Err(LiftError::Source(message))
                if message.contains("implicit local register index is out of range")
        ),
        "the committed SWF declares two locals but accesses local register two"
    );
}

fn swf_fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates parent")
        .parent()
        .expect("workspace root")
        .join("corpus")
        .join("flash")
        .join("swf")
        .join("synthetic")
        .join("synthetic_counter_fws.swf")
}

#[test]
fn lift_is_deterministic() {
    let first: NirModule = lifted_nir();
    let second: NirModule = lifted_nir();
    assert_eq!(first, second, "the AVM2 lift must be byte-stable");
}
