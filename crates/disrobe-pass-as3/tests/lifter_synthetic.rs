#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::doc_markdown,
    clippy::pedantic,
    clippy::nursery
)]

//! Spec-accurate hand-assembled ABC fixtures that exercise the AVM2
//! method-body lifter end to end. Each fixture is a complete `abcFile`
//! (cpool + method_info + instance_info + class_info + method_body) built byte
//! by byte against the Adobe AVM2 overview, parsed by the production parser,
//! and asserted to recover the intended control flow, property access, and
//! literals. No production code is referenced for the expected output, so the
//! oracle is the hand-written AS3 source these bytecodes were written to model.

use disrobe_pass_as3::abc::{ABC_MAJOR, ABC_MINOR, AbcFile, MethodBody, parse};
use disrobe_pass_as3::decompile::render_class_skeleton;
use disrobe_pass_as3::lifter::{LiftedBody, LocalNames, lift_body, local_names_for, render_body};

fn u30(mut value: u32, out: &mut Vec<u8>) {
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
}

fn s24(value: i32, out: &mut Vec<u8>) {
    let raw: u32 = value as u32;
    out.push((raw & 0xFF) as u8);
    out.push(((raw >> 8) & 0xFF) as u8);
    out.push(((raw >> 16) & 0xFF) as u8);
}

/// Constant-pool layout shared by every fixture. Index 0 is the implicit `*`
/// / `any` sentinel in every sub-pool, matching the ABC spec.
struct PoolBuilder {
    integers: Vec<i32>,
    strings: Vec<String>,
    namespaces: Vec<(u8, u32)>,
    multinames: Vec<MnSpec>,
}

#[derive(Clone)]
enum MnSpec {
    QName { ns: u32, name: u32 },
}

impl PoolBuilder {
    fn new() -> Self {
        Self {
            integers: vec![0],
            strings: vec![String::new()],
            namespaces: vec![(0, 0)],
            multinames: vec![MnSpec::QName { ns: 0, name: 0 }],
        }
    }

    fn intern_string(&mut self, s: &str) -> u32 {
        if let Some(pos) = self.strings.iter().position(|x: &String| x == s) {
            return pos as u32;
        }
        self.strings.push(s.to_owned());
        (self.strings.len() - 1) as u32
    }

    fn intern_int(&mut self, v: i32) -> u32 {
        if let Some(pos) = self.integers.iter().position(|x: &i32| *x == v) {
            return pos as u32;
        }
        self.integers.push(v);
        (self.integers.len() - 1) as u32
    }

    fn intern_ns(&mut self, kind: u8, name: &str) -> u32 {
        let name_idx: u32 = self.intern_string(name);
        self.namespaces.push((kind, name_idx));
        (self.namespaces.len() - 1) as u32
    }

    fn intern_qname(&mut self, ns: u32, name: &str) -> u32 {
        let name_idx: u32 = self.intern_string(name);
        self.multinames.push(MnSpec::QName { ns, name: name_idx });
        (self.multinames.len() - 1) as u32
    }

    fn emit(&self, out: &mut Vec<u8>) {
        u30(self.integers.len() as u32, out);
        for v in &self.integers[1..] {
            u30(*v as u32, out);
        }
        u30(1, out);
        u30(1, out);
        u30(self.strings.len() as u32, out);
        for s in &self.strings[1..] {
            u30(s.len() as u32, out);
            out.extend_from_slice(s.as_bytes());
        }
        u30(self.namespaces.len() as u32, out);
        for (kind, name_idx) in &self.namespaces[1..] {
            out.push(*kind);
            u30(*name_idx, out);
        }
        u30(1, out);
        u30(self.multinames.len() as u32, out);
        for mn in &self.multinames[1..] {
            match mn {
                MnSpec::QName { ns, name } => {
                    out.push(0x07);
                    u30(*ns, out);
                    u30(*name, out);
                }
            }
        }
    }
}

struct MethodSpec {
    return_type: u32,
    param_types: Vec<u32>,
    name: u32,
    param_names: Vec<u32>,
}

fn emit_method_info(m: &MethodSpec, out: &mut Vec<u8>) {
    u30(m.param_types.len() as u32, out);
    u30(m.return_type, out);
    for p in &m.param_types {
        u30(*p, out);
    }
    u30(m.name, out);
    let flags: u8 = if m.param_names.is_empty() { 0x00 } else { 0x80 };
    out.push(flags);
    for pn in &m.param_names {
        u30(*pn, out);
    }
}

struct BodySpec {
    method: u32,
    max_stack: u32,
    local_count: u32,
    code: Vec<u8>,
}

fn emit_body(b: &BodySpec, out: &mut Vec<u8>) {
    u30(b.method, out);
    u30(b.max_stack, out);
    u30(b.local_count, out);
    u30(1, out);
    u30(b.max_stack.max(1), out);
    u30(b.code.len() as u32, out);
    out.extend_from_slice(&b.code);
    u30(0, out);
    u30(0, out);
}

/// Assemble a complete single-class ABC. `methods` and `bodies` are emitted in
/// order; the class declares one instance method per (trait_name, method_idx).
struct AbcSpec {
    pool: PoolBuilder,
    methods: Vec<MethodSpec>,
    bodies: Vec<BodySpec>,
    class_name_mn: u32,
    super_mn: u32,
    iinit: u32,
    method_traits: Vec<(u32, u32, u8)>,
}

fn assemble(spec: &AbcSpec) -> Vec<u8> {
    let mut b: Vec<u8> = Vec::new();
    b.extend_from_slice(&ABC_MINOR.to_le_bytes());
    b.extend_from_slice(&ABC_MAJOR.to_le_bytes());
    spec.pool.emit(&mut b);

    u30(spec.methods.len() as u32, &mut b);
    for m in &spec.methods {
        emit_method_info(m, &mut b);
    }

    u30(0, &mut b);

    u30(1, &mut b);
    u30(spec.class_name_mn, &mut b);
    u30(spec.super_mn, &mut b);
    b.push(0x00);
    u30(0, &mut b);
    u30(spec.iinit, &mut b);
    u30(spec.method_traits.len() as u32, &mut b);
    for (name_mn, method_idx, kind) in &spec.method_traits {
        u30(*name_mn, &mut b);
        b.push(*kind);
        u30(0, &mut b);
        u30(*method_idx, &mut b);
    }

    u30(0, &mut b);
    u30(0, &mut b);

    u30(1, &mut b);
    u30(0, &mut b);
    u30(0, &mut b);

    u30(spec.bodies.len() as u32, &mut b);
    for body in &spec.bodies {
        emit_body(body, &mut b);
    }
    b
}

fn parse_fixture(bytes: &[u8]) -> AbcFile {
    parse(bytes).expect("hand-assembled ABC must parse")
}

#[test]
fn lifts_property_call_with_string_literal() {
    let mut pool: PoolBuilder = PoolBuilder::new();
    let pkg_ns: u32 = pool.intern_ns(0x16, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Greeter");
    let obj_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let trace_mn: u32 = pool.intern_qname(pkg_ns, "trace");
    let greet_mn: u32 = pool.intern_qname(pkg_ns, "greet");
    let hello: u32 = pool.intern_string("Hello, World");

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD0);
    code.push(0x30);
    code.push(0x5D);
    u30(trace_mn, &mut code);
    code.push(0x2C);
    u30(hello, &mut code);
    code.push(0x4F);
    u30(trace_mn, &mut code);
    u30(1, &mut code);
    code.push(0x47);

    let spec: AbcSpec = AbcSpec {
        pool,
        methods: vec![
            MethodSpec {
                return_type: 0,
                param_types: vec![],
                name: 0,
                param_names: vec![],
            },
            MethodSpec {
                return_type: 0,
                param_types: vec![],
                name: greet_mn,
                param_names: vec![],
            },
        ],
        bodies: vec![BodySpec {
            method: 1,
            max_stack: 2,
            local_count: 1,
            code,
        }],
        class_name_mn: class_mn,
        super_mn: obj_mn,
        iinit: 0,
        method_traits: vec![(greet_mn, 1, 0x01)],
    };

    let abc: AbcFile = parse_fixture(&assemble(&spec));
    let body: &MethodBody = &abc.method_bodies[0];
    let lifted: LiftedBody = lift_body(&abc, body, abc.methods.get(1)).expect("lift");
    let names: LocalNames = local_names_for(&abc, abc.methods.get(1));
    let rendered: String = render_body(&lifted, &names, "");

    assert!(
        rendered.contains("trace(\"Hello, World\")"),
        "expected lifted call with literal, got:\n{rendered}"
    );
    assert!(
        rendered.contains("return;"),
        "expected void return: {rendered}"
    );
    assert!(lifted.recovered, "body must be marked recovered");
}

#[test]
fn lifts_arithmetic_return() {
    let mut pool: PoolBuilder = PoolBuilder::new();
    let pkg_ns: u32 = pool.intern_ns(0x16, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Calc");
    let obj_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let add_mn: u32 = pool.intern_qname(pkg_ns, "addOne");
    let _seven: u32 = pool.intern_int(7);

    let code: Vec<u8> = vec![0xD1, 0x24, 0x01, 0xA0, 0x48];

    let spec: AbcSpec = AbcSpec {
        pool,
        methods: vec![
            MethodSpec {
                return_type: 0,
                param_types: vec![],
                name: 0,
                param_names: vec![],
            },
            MethodSpec {
                return_type: 0,
                param_types: vec![obj_mn],
                name: add_mn,
                param_names: vec![],
            },
        ],
        bodies: vec![BodySpec {
            method: 1,
            max_stack: 2,
            local_count: 2,
            code,
        }],
        class_name_mn: class_mn,
        super_mn: obj_mn,
        iinit: 0,
        method_traits: vec![(add_mn, 1, 0x01)],
    };

    let abc: AbcFile = parse_fixture(&assemble(&spec));
    let lifted: LiftedBody =
        lift_body(&abc, &abc.method_bodies[0], abc.methods.get(1)).expect("lift");
    let names: LocalNames = local_names_for(&abc, abc.methods.get(1));
    let rendered: String = render_body(&lifted, &names, "");
    assert!(
        rendered.contains("return (arg1 + 1);"),
        "expected arithmetic return, got:\n{rendered}"
    );
}

#[test]
fn lifts_conditional_branch_to_goto() {
    let mut pool: PoolBuilder = PoolBuilder::new();
    let pkg_ns: u32 = pool.intern_ns(0x16, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Branchy");
    let obj_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let m_mn: u32 = pool.intern_qname(pkg_ns, "check");

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD1);
    code.push(0x24);
    code.push(0x00);
    let if_pos: usize = code.len();
    code.push(0x14);
    s24(0, &mut code);
    let after_if: usize = code.len();
    code.push(0x24);
    code.push(0x01);
    code.push(0x48);
    let label_off: usize = code.len();
    code.push(0x24);
    code.push(0x00);
    code.push(0x48);
    let rel: i32 = (label_off as i32) - (after_if as i32);
    let patch: u32 = rel as u32;
    code[if_pos + 1] = (patch & 0xFF) as u8;
    code[if_pos + 2] = ((patch >> 8) & 0xFF) as u8;
    code[if_pos + 3] = ((patch >> 16) & 0xFF) as u8;

    let spec: AbcSpec = AbcSpec {
        pool,
        methods: vec![
            MethodSpec {
                return_type: 0,
                param_types: vec![],
                name: 0,
                param_names: vec![],
            },
            MethodSpec {
                return_type: 0,
                param_types: vec![obj_mn],
                name: m_mn,
                param_names: vec![],
            },
        ],
        bodies: vec![BodySpec {
            method: 1,
            max_stack: 2,
            local_count: 2,
            code,
        }],
        class_name_mn: class_mn,
        super_mn: obj_mn,
        iinit: 0,
        method_traits: vec![(m_mn, 1, 0x01)],
    };

    let abc: AbcFile = parse_fixture(&assemble(&spec));
    let lifted: LiftedBody =
        lift_body(&abc, &abc.method_bodies[0], abc.methods.get(1)).expect("lift");
    let names: LocalNames = local_names_for(&abc, abc.methods.get(1));
    let rendered: String = render_body(&lifted, &names, "");
    assert!(
        rendered.contains("if ((arg1 != 0)) goto L"),
        "expected ifne lowered to conditional goto, got:\n{rendered}"
    );
    assert!(
        rendered.matches("return").count() == 2,
        "both return paths must be present, got:\n{rendered}"
    );
    assert!(
        rendered.contains(':'),
        "branch target label must be emitted, got:\n{rendered}"
    );
}

#[test]
fn full_class_skeleton_has_lifted_method_body() {
    let mut pool: PoolBuilder = PoolBuilder::new();
    let pkg_ns: u32 = pool.intern_ns(0x16, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Greeter");
    let obj_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let trace_mn: u32 = pool.intern_qname(pkg_ns, "trace");
    let greet_mn: u32 = pool.intern_qname(pkg_ns, "greet");
    let hi: u32 = pool.intern_string("hi");

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD0);
    code.push(0x30);
    code.push(0x5D);
    u30(trace_mn, &mut code);
    code.push(0x2C);
    u30(hi, &mut code);
    code.push(0x4F);
    u30(trace_mn, &mut code);
    u30(1, &mut code);
    code.push(0x47);

    let spec: AbcSpec = AbcSpec {
        pool,
        methods: vec![
            MethodSpec {
                return_type: 0,
                param_types: vec![],
                name: 0,
                param_names: vec![],
            },
            MethodSpec {
                return_type: 0,
                param_types: vec![],
                name: greet_mn,
                param_names: vec![],
            },
        ],
        bodies: vec![BodySpec {
            method: 1,
            max_stack: 2,
            local_count: 1,
            code,
        }],
        class_name_mn: class_mn,
        super_mn: obj_mn,
        iinit: 0,
        method_traits: vec![(greet_mn, 1, 0x01)],
    };

    let abc: AbcFile = parse_fixture(&assemble(&spec));
    let skel: String = render_class_skeleton(&abc, &abc.instances[0]).expect("skeleton");
    assert!(skel.contains("class Greeter"), "class decl: {skel}");
    assert!(
        skel.contains("public function greet(): "),
        "method signature must be rendered: {skel}"
    );
    assert!(
        skel.contains("trace(\"hi\")"),
        "method body must be lifted, not stubbed: {skel}"
    );
    assert!(
        !skel.contains("/* method */"),
        "old stub marker must be gone: {skel}"
    );
}

/// Honest recovery measurement: assemble a class whose four instance methods
/// each carry a substantive body, then confirm the lifter renders a non-empty
/// body for every one and the old stub markers never appear. Before this work
/// every method rendered as `{ /* method */ }` (0/N bodies); the assertion
/// here is the after-state floor (4/4).
#[test]
fn measures_method_body_recovery_rate() {
    let mut pool: PoolBuilder = PoolBuilder::new();
    let pkg_ns: u32 = pool.intern_ns(0x16, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Widget");
    let obj_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let trace_mn: u32 = pool.intern_qname(pkg_ns, "trace");
    let value_mn: u32 = pool.intern_qname(pkg_ns, "value");
    let label: u32 = pool.intern_string("w");

    let m_names: [u32; 4] = [
        pool.intern_qname(pkg_ns, "init"),
        pool.intern_qname(pkg_ns, "scale"),
        pool.intern_qname(pkg_ns, "log"),
        pool.intern_qname(pkg_ns, "clamp"),
    ];

    let mut init_code: Vec<u8> = Vec::new();
    init_code.push(0xD0);
    init_code.push(0xD1);
    init_code.push(0x61);
    u30(value_mn, &mut init_code);
    init_code.push(0x47);

    let scale_code: Vec<u8> = vec![0xD1, 0x24, 0x02, 0xA2, 0x48];

    let mut log_code: Vec<u8> = Vec::new();
    log_code.push(0xD0);
    log_code.push(0x30);
    log_code.push(0x5D);
    u30(trace_mn, &mut log_code);
    log_code.push(0x2C);
    u30(label, &mut log_code);
    log_code.push(0x4F);
    u30(trace_mn, &mut log_code);
    u30(1, &mut log_code);
    log_code.push(0x47);

    let clamp_code: Vec<u8> = vec![0xD1, 0x24, 0x00, 0x14, 0x00, 0x00, 0x00, 0x24, 0x00, 0x48];

    let bodies: Vec<BodySpec> = vec![
        BodySpec {
            method: 1,
            max_stack: 2,
            local_count: 1,
            code: init_code,
        },
        BodySpec {
            method: 2,
            max_stack: 2,
            local_count: 2,
            code: scale_code,
        },
        BodySpec {
            method: 3,
            max_stack: 2,
            local_count: 1,
            code: log_code,
        },
        BodySpec {
            method: 4,
            max_stack: 2,
            local_count: 2,
            code: clamp_code,
        },
    ];

    let methods: Vec<MethodSpec> = (0..=4)
        .map(|i: u32| MethodSpec {
            return_type: 0,
            param_types: if i == 0 { vec![] } else { vec![obj_mn] },
            name: if i == 0 { 0 } else { m_names[(i - 1) as usize] },
            param_names: vec![],
        })
        .collect();

    let spec: AbcSpec = AbcSpec {
        pool,
        methods,
        bodies,
        class_name_mn: class_mn,
        super_mn: obj_mn,
        iinit: 0,
        method_traits: vec![
            (m_names[0], 1, 0x01),
            (m_names[1], 2, 0x01),
            (m_names[2], 3, 0x01),
            (m_names[3], 4, 0x01),
        ],
    };

    let abc: AbcFile = parse_fixture(&assemble(&spec));
    let mut lifted_bodies: usize = 0;
    let total: usize = abc.method_bodies.len();
    for (i, body) in abc.method_bodies.iter().enumerate() {
        let info: Option<&disrobe_pass_as3::abc::MethodInfo> = abc.methods.get(i + 1);
        let lifted: LiftedBody = lift_body(&abc, body, info).expect("lift");
        let names: LocalNames = local_names_for(&abc, info);
        let rendered: String = render_body(&lifted, &names, "");
        if !rendered.trim().is_empty() {
            lifted_bodies += 1;
        }
    }
    assert_eq!(
        lifted_bodies, total,
        "every substantive method body must lift to non-empty pseudocode"
    );

    let skel: String = render_class_skeleton(&abc, &abc.instances[0]).expect("skeleton");
    assert!(
        !skel.contains("/* method */") && !skel.contains("/* getter */"),
        "no stub markers may remain: {skel}"
    );
    assert!(
        skel.contains("this.value = arg1;"),
        "property assignment must be recovered: {skel}"
    );
    assert!(
        skel.contains("return (arg1 * 2);"),
        "arithmetic return must be recovered: {skel}"
    );
    assert!(
        skel.contains("trace(\"w\")"),
        "call recovery must be present: {skel}"
    );
    assert!(
        skel.contains("goto L"),
        "branch recovery must be present: {skel}"
    );
}
