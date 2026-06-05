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

//! Hand-assembled ABC fixtures that exercise the AVM2 method-body lifter.

use disrobe_pass_as3::abc::{
    ABC_MAJOR, ABC_MINOR, AbcFile, ConstantPool, InstanceInfo, MethodBody, MethodInfo, Multiname,
    Namespace, TraitInfo, parse,
};
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

/// Constant-pool layout shared by every fixture.
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

/// Assemble a complete single-class ABC.
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
    assert!(
        lifted.fully_recovered,
        "body must be marked fully recovered (no dropped/opaque ops): {:?}",
        lifted.fidelity_warning()
    );
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
        rendered.contains("if ((arg1 == 0)) {"),
        "ifne skip must structure into a negated if-block, got:\n{rendered}"
    );
    assert!(
        rendered.contains("return 1;") && rendered.contains("return 0;"),
        "both return paths must be present, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("goto"),
        "single-entry forward branch must not leave a goto, got:\n{rendered}"
    );
}

#[test]
fn structures_forward_conditional_skip_into_if_block() {
    let mut pool: PoolBuilder = PoolBuilder::new();
    let pkg_ns: u32 = pool.intern_ns(0x16, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Guard");
    let obj_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let m_mn: u32 = pool.intern_qname(pkg_ns, "run");
    let flag_mn: u32 = pool.intern_qname(pkg_ns, "flag");

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD1);
    code.push(0x24);
    code.push(0x00);
    let if_pos: usize = code.len();
    code.push(0x13);
    s24(0, &mut code);
    let after_if: usize = code.len();
    code.push(0xD0);
    code.push(0x26);
    code.push(0x61);
    u30(flag_mn, &mut code);
    let label_off: usize = code.len();
    code.push(0x47);
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
        rendered.contains("if ((arg1 != 0)) {"),
        "ifeq skip must negate to != and open a block, got:\n{rendered}"
    );
    assert!(
        rendered.contains("    this.flag = true;"),
        "block body must be indented one level deeper, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("goto"),
        "no goto should remain, got:\n{rendered}"
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
    let mut fully_recovered: usize = 0;
    let total: usize = abc.method_bodies.len();
    for (i, body) in abc.method_bodies.iter().enumerate() {
        let info: Option<&disrobe_pass_as3::abc::MethodInfo> = abc.methods.get(i + 1);
        let lifted: LiftedBody = lift_body(&abc, body, info).expect("lift");
        if lifted.fully_recovered {
            fully_recovered += 1;
        }
    }
    assert_eq!(
        fully_recovered, total,
        "every method must lift with full fidelity (no dropped/opaque ops)"
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

/// Build an `AbcFile` directly (no byte round-trip) for per-opcode tests.
fn mk_abc(
    strings: &[&str],
    qnames: &[(u32, u32)],
    instance_traits: Vec<TraitInfo>,
    methods: Vec<MethodInfo>,
    code: Vec<u8>,
) -> AbcFile {
    let mut cpool: ConstantPool = ConstantPool {
        strings: strings.iter().map(|s: &&str| (*s).to_owned()).collect(),
        ..ConstantPool::default()
    };
    cpool.namespaces = vec![
        Namespace {
            kind: 0,
            name_index: 0,
        },
        Namespace {
            kind: 0x16,
            name_index: 0,
        },
    ];
    cpool.multinames = vec![Multiname::QName {
        ns_index: 0,
        name_index: 0,
    }];
    for (ns, name) in qnames {
        cpool.multinames.push(Multiname::QName {
            ns_index: *ns,
            name_index: *name,
        });
    }
    let body: MethodBody = MethodBody {
        method: (methods.len().saturating_sub(1)) as u32,
        max_stack: 8,
        local_count: 8,
        init_scope_depth: 0,
        max_scope_depth: 1,
        code,
        exceptions: Vec::new(),
        traits: Vec::new(),
    };
    let instance: InstanceInfo = InstanceInfo {
        name_index: 1,
        super_index: 0,
        flags: 0,
        protected_ns: 0,
        interfaces: Vec::new(),
        iinit: 0,
        traits: instance_traits,
    };
    AbcFile {
        minor: 16,
        major: 46,
        cpool,
        methods,
        metadata_count: 0,
        instances: vec![instance],
        classes: Vec::new(),
        scripts: Vec::new(),
        method_bodies: vec![body],
    }
}

fn slot_trait(name_index: u32, slot_id: u32) -> TraitInfo {
    TraitInfo {
        name_index,
        kind: 0x00,
        slot_id,
        method_index: 0,
        type_name: 0,
    }
}

fn one_param_method() -> Vec<MethodInfo> {
    vec![
        MethodInfo {
            return_type: 0,
            param_types: Vec::new(),
            name_index: 0,
            flags: 0,
            param_names: Vec::new(),
        },
        MethodInfo {
            return_type: 0,
            param_types: vec![2],
            name_index: 4,
            flags: 0,
            param_names: Vec::new(),
        },
    ]
}

fn lift_only(abc: &AbcFile) -> (String, LiftedBody) {
    let info: Option<&MethodInfo> = abc.methods.get(1);
    let lifted: LiftedBody = lift_body(abc, &abc.method_bodies[0], info).expect("lift");
    let names: LocalNames = local_names_for(abc, info);
    let rendered: String = render_body(&lifted, &names, "");
    (rendered, lifted)
}

#[test]
fn lifts_getsuper_and_setsuper() {
    let code: Vec<u8> = vec![0xD0, 0xD1, 0x05, 0x03, 0xD0, 0x04, 0x03, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "Sub", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("super.x = arg1;"),
        "setsuper must render super assignment: {rendered}"
    );
    assert!(
        rendered.contains("return super.x;"),
        "getsuper must render super read: {rendered}"
    );
    assert!(
        lifted.fully_recovered,
        "no ops dropped: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_deleteproperty() {
    let code: Vec<u8> = vec![0xD0, 0x6A, 0x03, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return delete this.field;"),
        "deleteproperty must render delete: {rendered}"
    );
    assert!(lifted.fully_recovered);
}

#[test]
fn lifts_getdescendants_e4x() {
    let code: Vec<u8> = vec![0xD0, 0x59, 0x03, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "item", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return this..item;"),
        "getdescendants must render E4X descendants: {rendered}"
    );
    assert!(lifted.fully_recovered);
}

#[test]
fn lifts_applytype_vector() {
    let code: Vec<u8> = vec![0x5D, 0x02, 0x60, 0x03, 0x53, 0x01, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "Vector", "int", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("Vector.<int>"),
        "applytype must render generic application: {rendered}"
    );
    assert!(lifted.fully_recovered);
}

#[test]
fn lifts_newfunction_closure() {
    let code: Vec<u8> = vec![0x40, 0x00, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("function()") && rendered.contains("closure method #0"),
        "newfunction must render a closure marker: {rendered}"
    );
    assert!(lifted.fully_recovered);
}

#[test]
fn lifts_istype_and_istypelate() {
    let code_static: Vec<u8> = vec![0xD1, 0xB2, 0x02, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "String", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code_static,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return (arg1 is String);"),
        "istype must render an `is` test: {rendered}"
    );
    assert!(lifted.fully_recovered);

    let code_late: Vec<u8> = vec![0xD1, 0x60, 0x02, 0xB3, 0x48];
    let abc2: AbcFile = mk_abc(
        &["", "C", "String", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code_late,
    );
    let (rendered2, lifted2): (String, LiftedBody) = lift_only(&abc2);
    assert!(
        rendered2.contains("return (arg1 is String);"),
        "istypelate must render an `is` test: {rendered2}"
    );
    assert!(lifted2.fully_recovered);
}

#[test]
fn resolves_getslot_setslot_to_trait_names() {
    let code: Vec<u8> = vec![0xD0, 0xD1, 0x6D, 0x05, 0xD0, 0x6C, 0x05, 0x48];
    let traits: Vec<TraitInfo> = vec![slot_trait(3, 5)];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "count", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        traits,
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("this.count = arg1;"),
        "setslot must resolve to the trait name `count`: {rendered}"
    );
    assert!(
        rendered.contains("return this.count;"),
        "getslot must resolve to the trait name `count`: {rendered}"
    );
    assert!(
        !rendered.contains("slot5"),
        "resolved slot must not fall back to slotN: {rendered}"
    );
    assert!(lifted.fully_recovered);
}

#[test]
fn unresolved_getslot_falls_back_honestly() {
    let code: Vec<u8> = vec![0xD0, 0x6C, 0x09, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("slot9"),
        "an undeclared slot must stay slotN, not invent a name: {rendered}"
    );
    assert!(lifted.fully_recovered, "getslot itself is modelled");
}

#[test]
fn lifts_forin_iteration_primitives() {
    let code: Vec<u8> = vec![0xD0, 0xD1, 0x23, 0x63, 0x02, 0x47];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("nextValue(arg1)"),
        "nextvalue must lower to a nextValue() call: {rendered}"
    );
    assert!(
        lifted.fully_recovered,
        "for-in primitives must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
}
