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

struct PoolBuilder {
    integers: Vec<i32>,
    strings: Vec<String>,
    namespaces: Vec<(u8, u32)>,
    multinames: Vec<MnSpec>,
}

#[derive(Clone)]
enum MnSpec {
    QName { ns: u32, name: u32 },
    QNameA { ns: u32, name: u32 },
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

    fn intern_qname_attr(&mut self, ns: u32, name: &str) -> u32 {
        let name_idx: u32 = self.intern_string(name);
        self.multinames.push(MnSpec::QNameA { ns, name: name_idx });
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
                MnSpec::QNameA { ns, name } => {
                    out.push(0x0D);
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
        lifted.structurally_recovered,
        "body must be marked structurally recovered (no dropped/opaque ops): {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_e4x_attribute_getproperty_with_at_sigil() {
    let mut pool: PoolBuilder = PoolBuilder::new();
    let pkg_ns: u32 = pool.intern_ns(0x16, "");
    let class_mn: u32 = pool.intern_qname(pkg_ns, "Reader");
    let obj_mn: u32 = pool.intern_qname(pkg_ns, "Object");
    let read_mn: u32 = pool.intern_qname(pkg_ns, "readId");
    let attr_mn: u32 = pool.intern_qname_attr(pkg_ns, "id");

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD0);
    code.push(0x66);
    u30(attr_mn, &mut code);
    code.push(0x48);

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
                name: read_mn,
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
        method_traits: vec![(read_mn, 1, 0x01)],
    };

    let abc: AbcFile = parse_fixture(&assemble(&spec));
    let lifted: LiftedBody =
        lift_body(&abc, &abc.method_bodies[0], abc.methods.get(1)).expect("lift");
    let names: LocalNames = local_names_for(&abc, abc.methods.get(1));
    let rendered: String = render_body(&lifted, &names, "");
    assert!(
        rendered.contains("return this.@id;"),
        "an E4X attribute access must decompile with the @ sigil, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("this.id"),
        "the attribute accessor must not collapse to a child-property access, got:\n{rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "attribute getproperty body must be structurally recovered: {:?}",
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
    let mut structurally_recovered: usize = 0;
    let mut with_residual_goto: usize = 0;
    let total: usize = abc.method_bodies.len();
    for (i, body) in abc.method_bodies.iter().enumerate() {
        let info: Option<&disrobe_pass_as3::abc::MethodInfo> = abc.methods.get(i + 1);
        let lifted: LiftedBody = lift_body(&abc, body, info).expect("lift");
        if lifted.structurally_recovered {
            structurally_recovered += 1;
        }
        if !lifted.fully_structured {
            with_residual_goto += 1;
            assert!(
                lifted
                    .fidelity_warning()
                    .is_some_and(|w: String| w.contains("not fully restructured")),
                "an unstructured body must declare its residual graph honestly"
            );
        }
    }
    assert_eq!(
        with_residual_goto, 0,
        "the degenerate zero-displacement branch now collapses as a dead effect-free no-op"
    );
    assert_eq!(
        structurally_recovered, total,
        "every body meets the structural recovery conditions once the dead zero-displacement branch is elided"
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
        !skel.contains("goto L"),
        "the dead zero-displacement branch must not leave a residual goto: {skel}"
    );
}

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

fn mk_abc_with_runtime_name(strings: &[&str], qnames: &[(u32, u32)]) -> (AbcFile, u32) {
    let mut abc: AbcFile = mk_abc(strings, qnames, Vec::new(), one_param_method(), Vec::new());
    let runtime_idx: u32 = abc.cpool.multinames.len() as u32;
    abc.cpool
        .multinames
        .push(Multiname::MultinameL { ns_set_index: 0 });
    (abc, runtime_idx)
}

fn mk_abc_with_multiname(strings: &[&str], qnames: &[(u32, u32)], mn: Multiname) -> (AbcFile, u32) {
    let mut abc: AbcFile = mk_abc(strings, qnames, Vec::new(), one_param_method(), Vec::new());
    let idx: u32 = abc.cpool.multinames.len() as u32;
    abc.cpool.multinames.push(mn);
    (abc, idx)
}

fn body_with_code(abc: AbcFile, code: Vec<u8>) -> AbcFile {
    AbcFile {
        method_bodies: vec![MethodBody {
            method: abc.method_bodies[0].method,
            max_stack: 8,
            local_count: 8,
            init_scope_depth: 0,
            max_scope_depth: 1,
            code,
            exceptions: Vec::new(),
            traits: Vec::new(),
        }],
        ..abc
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
        lifted.structurally_recovered,
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
    assert!(lifted.structurally_recovered);
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
    assert!(lifted.structurally_recovered);
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
    assert!(lifted.structurally_recovered);
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
    assert!(lifted.structurally_recovered);
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
    assert!(lifted.structurally_recovered);

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
    assert!(lifted2.structurally_recovered);
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
    assert!(lifted.structurally_recovered);
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
    assert!(lifted.structurally_recovered, "getslot itself is modelled");
}

#[test]
fn lifts_lookupswitch_with_real_case_targets() {
    use disrobe_pass_as3::lifter::{CaseLabel, Stmt, SwitchCase};

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD1);
    let sw_pos: usize = code.len();
    code.push(0x1B);
    let default_patch: usize = code.len();
    s24(0, &mut code);
    u30(1, &mut code);
    let case0_patch: usize = code.len();
    s24(0, &mut code);
    let case1_patch: usize = code.len();
    s24(0, &mut code);
    let case0_off: usize = code.len();
    code.push(0x24);
    code.push(0x0A);
    code.push(0x48);
    let case1_off: usize = code.len();
    code.push(0x24);
    code.push(0x14);
    code.push(0x48);
    let default_off: usize = code.len();
    code.push(0x24);
    code.push(0x00);
    code.push(0x48);

    let patch = |code: &mut Vec<u8>, at: usize, target: usize| {
        let rel: i32 = target as i32 - sw_pos as i32;
        let raw: u32 = rel as u32;
        code[at] = (raw & 0xFF) as u8;
        code[at + 1] = ((raw >> 8) & 0xFF) as u8;
        code[at + 2] = ((raw >> 16) & 0xFF) as u8;
    };
    patch(&mut code, default_patch, default_off);
    patch(&mut code, case0_patch, case0_off);
    patch(&mut code, case1_patch, case1_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let _ = (case0_off, case1_off, default_off);
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let switch: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::StructuredSwitch { .. }))
        .expect("the dense lookupswitch must fold into a structured switch with real bodies");
    let Stmt::StructuredSwitch { cases, .. } = switch else {
        unreachable!()
    };
    assert_eq!(cases.len(), 3, "two value cases plus the default arm");
    assert_eq!(
        cases[0].labels,
        vec![CaseLabel::Value(0)],
        "first segment is selector value 0"
    );
    assert_eq!(
        cases[1].labels,
        vec![CaseLabel::Value(1)],
        "second segment is selector value 1"
    );
    assert_eq!(
        cases[2].labels,
        vec![CaseLabel::Default],
        "last segment is the default fallback"
    );
    assert!(
        cases
            .iter()
            .all(|c: &SwitchCase| c.body.len() == 1 && !c.breaks),
        "each case body is a single returning statement with no break needed: {cases:?}"
    );

    assert!(
        rendered.contains("switch (arg1) {")
            && rendered.contains("    case 0:")
            && rendered.contains("    case 1:")
            && rendered.contains("    default:"),
        "switch must render real case dispatch with structured arms: {rendered}"
    );
    assert!(
        rendered.contains("        return 10;")
            && rendered.contains("        return 20;")
            && rendered.contains("        return 0;"),
        "each case body must be rendered under its label, not a goto: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains("cases */"),
        "no goto dispatch or stub marker may remain: {rendered}"
    );
}

#[test]
fn structures_switch_with_breaks_and_default_fallthrough() {
    use disrobe_pass_as3::lifter::{CaseLabel, Stmt};

    let mut code: Vec<u8> = vec![0x24, 0x00, 0xD6, 0xD1];
    let sw_pos: usize = code.len();
    code.push(0x1B);
    let default_patch: usize = code.len();
    s24(0, &mut code);
    u30(1, &mut code);
    let case0_patch: usize = code.len();
    s24(0, &mut code);
    let case1_patch: usize = code.len();
    s24(0, &mut code);

    let case0_off: usize = code.len();
    code.push(0x24);
    code.push(0x64);
    code.push(0xD6);
    code.push(0x10);
    let break0_operand: usize = code.len();
    s24(0, &mut code);
    let after_break0: usize = code.len();

    let case1_off: usize = code.len();
    code.push(0x24);
    code.push(0x78);
    code.push(0xD6);
    code.push(0x10);
    let break1_operand: usize = code.len();
    s24(0, &mut code);
    let after_break1: usize = code.len();

    let default_off: usize = code.len();
    code.push(0x24);
    code.push(0x00);
    code.push(0xD6);

    let merge_off: usize = code.len();
    code.push(0xD2);
    code.push(0x48);

    let patch_sw = |code: &mut Vec<u8>, at: usize, target: usize| {
        let rel: i32 = target as i32 - sw_pos as i32;
        let raw: u32 = rel as u32;
        code[at] = (raw & 0xFF) as u8;
        code[at + 1] = ((raw >> 8) & 0xFF) as u8;
        code[at + 2] = ((raw >> 16) & 0xFF) as u8;
    };
    patch_sw(&mut code, default_patch, default_off);
    patch_sw(&mut code, case0_patch, case0_off);
    patch_sw(&mut code, case1_patch, case1_off);
    patch_branch(&mut code, break0_operand, after_break0, merge_off);
    patch_branch(&mut code, break1_operand, after_break1, merge_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "classify"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let switch: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::StructuredSwitch { .. }))
        .expect("a switch with break edges must fold into a structured switch");
    let Stmt::StructuredSwitch { cases, .. } = switch else {
        unreachable!()
    };
    assert_eq!(cases.len(), 3, "value 0, value 1, and default");
    assert_eq!(cases[0].labels, vec![CaseLabel::Value(0)]);
    assert!(cases[0].breaks, "case 0 ends in a break to the merge point");
    assert_eq!(cases[1].labels, vec![CaseLabel::Value(1)]);
    assert!(cases[1].breaks, "case 1 ends in a break to the merge point");
    assert_eq!(cases[2].labels, vec![CaseLabel::Default]);
    assert!(
        !cases[2].breaks,
        "the default arm flows into the merge point and needs no break: {:?}",
        cases[2]
    );

    assert!(
        rendered.contains("        loc2 = 100;\n        break;"),
        "case 0 body then break, in order and indented: {rendered}"
    );
    assert!(
        rendered.contains("        loc2 = 120;\n        break;"),
        "case 1 body then break: {rendered}"
    );
    assert!(
        rendered.contains("    default:\n        loc2 = 0;"),
        "default body present without a break: {rendered}"
    );
    assert!(
        rendered.contains("return loc2;"),
        "the post-switch merge continuation must survive: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains(&format!("L{merge_off}:")),
        "a reducible switch must leave no goto/label residue: {rendered}"
    );
}

#[test]
fn lifts_inclocal_i_to_in_place_increment() {
    let code: Vec<u8> = vec![0xC2, 0x01, 0x47];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("arg1 = (arg1 + 1);"),
        "inclocal_i must lower to an in-place increment: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "inclocal_i must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_declocal_to_in_place_decrement() {
    let code: Vec<u8> = vec![0x94, 0x01, 0x47];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("arg1 = (arg1 - 1);"),
        "declocal must lower to an in-place decrement: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_astypelate_to_as_cast() {
    let code: Vec<u8> = vec![0xD1, 0x60, 0x02, 0x87, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "String", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return (arg1 as String);"),
        "astypelate must render an `as` cast: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_callsupervoid_to_super_call() {
    let code: Vec<u8> = vec![0xD0, 0x2C, 0x00, 0x4E, 0x03, 0x01, 0x47];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "render", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("super.render("),
        "callsupervoid must render a super.method() call: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_dynamic_index_property_access() {
    let (abc, mn): (AbcFile, u32) = mk_abc_with_runtime_name(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
    );
    let mut code: Vec<u8> = vec![0xD0, 0xD1, 0x66];
    u30(mn, &mut code);
    code.push(0x48);
    let abc: AbcFile = AbcFile {
        method_bodies: vec![MethodBody {
            method: abc.method_bodies[0].method,
            max_stack: 8,
            local_count: 8,
            init_scope_depth: 0,
            max_scope_depth: 1,
            code,
            exceptions: Vec::new(),
            traits: Vec::new(),
        }],
        ..abc
    };
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return this[arg1];"),
        "runtime-name getproperty must synthesize computed indexing, not drop the index: {rendered}"
    );
    assert!(
        !rendered.contains("[name]"),
        "the [name] sentinel must not leak into source: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_dynamic_index_property_assignment() {
    let (abc, mn): (AbcFile, u32) = mk_abc_with_runtime_name(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
    );
    let mut code: Vec<u8> = vec![0xD0, 0xD1, 0x26, 0x61];
    u30(mn, &mut code);
    code.push(0x47);
    let abc: AbcFile = AbcFile {
        method_bodies: vec![MethodBody {
            method: abc.method_bodies[0].method,
            max_stack: 8,
            local_count: 8,
            init_scope_depth: 0,
            max_scope_depth: 1,
            code,
            exceptions: Vec::new(),
            traits: Vec::new(),
        }],
        ..abc
    };
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("this[arg1] = true;"),
        "runtime-name setproperty must synthesize a computed-index assignment: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_runtime_namespace_getproperty() {
    let (abc, mn): (AbcFile, u32) = mk_abc_with_multiname(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Multiname::RtqName { name_index: 3 },
    );
    let mut code: Vec<u8> = vec![0xD0, 0xD1, 0x66];
    u30(mn, &mut code);
    code.push(0x48);
    let abc: AbcFile = body_with_code(abc, code);
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return this[(arg1 :: field)];"),
        "runtime-namespace getproperty must pop the namespace, qualify the access, and stay balanced: {rendered}"
    );
    assert!(
        !rendered.contains("[ns]") && !rendered.contains("[name]"),
        "runtime multiname sentinels must not leak into source: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_runtime_namespace_and_name_getproperty() {
    let (abc, mn): (AbcFile, u32) = mk_abc_with_multiname(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Multiname::RtqNameL,
    );
    let mut code: Vec<u8> = vec![0xD0, 0xD1, 0xD2, 0x66];
    u30(mn, &mut code);
    code.push(0x48);
    let abc: AbcFile = body_with_code(abc, code);
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return this[(arg1 :: loc2)];"),
        "runtime ns+name getproperty must pop both operands and the object: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_runtime_namespace_setproperty() {
    let (abc, mn): (AbcFile, u32) = mk_abc_with_multiname(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Multiname::RtqName { name_index: 3 },
    );
    let mut code: Vec<u8> = vec![0xD0, 0xD1, 0x26, 0x61];
    u30(mn, &mut code);
    code.push(0x47);
    let abc: AbcFile = body_with_code(abc, code);
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("this[(arg1 :: field)] = true;"),
        "runtime-namespace setproperty must keep the qualifier and stack balance: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_runtime_name_computed_call() {
    let (abc, mn): (AbcFile, u32) = mk_abc_with_multiname(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Multiname::MultinameL { ns_set_index: 0 },
    );
    let mut code: Vec<u8> = vec![0xD0, 0xD1, 0x24, 0x05, 0x4F];
    u30(mn, &mut code);
    u30(1, &mut code);
    code.push(0x47);
    let abc: AbcFile = body_with_code(abc, code);
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("this[arg1](5);"),
        "runtime-name callpropvoid must recover computed dispatch and pop the runtime name: {rendered}"
    );
    assert!(
        !rendered.contains("[name]"),
        "the [name] sentinel must not leak into a computed call: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_runtime_name_computed_construct() {
    let (abc, mn): (AbcFile, u32) = mk_abc_with_multiname(
        &["", "C", "Object", "field", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Multiname::MultinameL { ns_set_index: 0 },
    );
    let mut code: Vec<u8> = vec![0xD0, 0xD1, 0x4A];
    u30(mn, &mut code);
    u30(0, &mut code);
    code.push(0x48);
    let abc: AbcFile = body_with_code(abc, code);
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return new this[arg1]();"),
        "runtime-name constructprop must recover a computed new-expression: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn getscopeobject_slot_renders_as_unqualified_name() {
    let code: Vec<u8> = vec![0x65, 0x00, 0x6C, 0x05, 0x48];
    let traits: Vec<TraitInfo> = vec![slot_trait(3, 5)];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "captured", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        traits,
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return captured;"),
        "a slot read off the scope object is an unqualified identifier: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "getscopeobject must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_alchemy_memory_load_and_store() {
    let load: Vec<u8> = vec![0xD1, 0x37, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        load,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return li32(arg1);"),
        "li32 must lower to an intrinsic load call: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "{:?}",
        lifted.fidelity_warning()
    );

    let store: Vec<u8> = vec![0x24, 0x2A, 0xD1, 0x3C, 0x47];
    let abc2: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        store,
    );
    let (rendered2, lifted2): (String, LiftedBody) = lift_only(&abc2);
    assert!(
        rendered2.contains("si32(42, arg1);"),
        "si32 must lower to an intrinsic store with value then address: {rendered2}"
    );
    assert!(
        lifted2.structurally_recovered,
        "{:?}",
        lifted2.fidelity_warning()
    );
}

#[test]
fn lifts_extended_avm2_stack_ops_without_dropping() {
    let code: Vec<u8> = vec![0xD1, 0x50, 0x83, 0x88, 0x81, 0x84, 0x79, 0x7B, 0x7A, 0x48];
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("sxi1(arg1)"),
        "sxi1 must preserve stack value through an intrinsic call: {rendered}"
    );
    assert!(
        rendered.contains("float4("),
        "float4 conversion must render instead of dropping: {rendered}"
    );
    assert!(
        lifted.dropped_opcodes.is_empty(),
        "extended AVM2 stack ops must be modelled, not dropped: {:?}",
        lifted.dropped_opcodes
    );
}

#[test]
fn lifts_float_constants_as_explicit_opaque_values() {
    let mut code: Vec<u8> = vec![0x22];
    u30(7, &mut code);
    code.push(0x48);
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return float7;"),
        "pushfloat must keep a stable placeholder expression: {rendered}"
    );
    assert!(
        lifted.dropped_opcodes.is_empty(),
        "pushfloat must not be reported as an unmodelled opcode: {:?}",
        lifted.dropped_opcodes
    );
    assert_eq!(lifted.opaque_operands, 1);
    assert!(
        !lifted.structurally_recovered,
        "opaque float constant must not claim structural recovery"
    );
}

#[test]
fn lifts_finddef_getouterscope_and_debug_metadata() {
    let mut code: Vec<u8> = vec![0xF2];
    u30(100, &mut code);
    code.push(0xF3);
    code.push(0x5F);
    u30(3, &mut code);
    code.push(0x29);
    code.push(0x67);
    u30(2, &mut code);
    code.push(0x48);
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return outerScope2;"),
        "getouterscope must emit a stable source expression: {rendered}"
    );
    assert!(
        lifted.dropped_opcodes.is_empty(),
        "finddef/getouterscope/debug metadata must not drop: {:?}",
        lifted.dropped_opcodes
    );
}

#[test]
fn lifts_callmethod_to_indexed_dispatch() {
    let mut code: Vec<u8> = vec![0xD1, 0x24, 0x05, 0x43];
    u30(7, &mut code);
    u30(1, &mut code);
    code.push(0x48);
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return arg1.methodSlot7(5);"),
        "callmethod must dispatch through the receiver at its disp_id, not drop: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "callmethod must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_callstatic_to_indexed_dispatch() {
    let mut code: Vec<u8> = vec![0xD1, 0x24, 0x09, 0x44];
    u30(3, &mut code);
    u30(1, &mut code);
    code.push(0x48);
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return arg1.method3(9);"),
        "callstatic must dispatch through the method-pool index, not drop: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "callstatic must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn structures_if_else_nested_in_while_loop() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = vec![0x24, 0x00, 0xD6];
    code.push(0x10);
    let entry_jump_operand: usize = code.len();
    s24(0, &mut code);
    let after_entry_jump: usize = code.len();

    let top_off: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x03);
    code.push(0x14);
    let ifne_operand: usize = code.len();
    s24(0, &mut code);
    let after_ifne: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x0A);
    code.push(0xA0);
    code.push(0xD6);
    code.push(0x10);
    let endif_jump_operand: usize = code.len();
    s24(0, &mut code);
    let after_endif_jump: usize = code.len();
    let else_off: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x01);
    code.push(0xA0);
    code.push(0xD6);

    let endif_off: usize = code.len();
    code.push(0xD2);
    code.push(0xD7);

    let test_off: usize = code.len();
    code.push(0xD2);
    code.push(0xD1);
    code.push(0x0F);
    let back_operand: usize = code.len();
    s24(0, &mut code);
    let after_back: usize = code.len();
    code.push(0xD2);
    code.push(0x48);

    patch_branch(&mut code, entry_jump_operand, after_entry_jump, test_off);
    patch_branch(&mut code, ifne_operand, after_ifne, else_off);
    patch_branch(&mut code, endif_jump_operand, after_endif_jump, endif_off);
    patch_branch(&mut code, back_operand, after_back, top_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let while_stmt: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::While { .. }))
        .expect("the bottom-test loop must structure into a while");
    let Stmt::While { body, .. } = while_stmt else {
        unreachable!()
    };
    assert!(
        body.iter().any(|s: &Stmt| matches!(s, Stmt::IfElse { .. })),
        "the loop body must nest a structured if/else, not raw branches: {body:?}"
    );

    assert!(
        rendered.contains("while ((loc2 < arg1)) {"),
        "outer while header recovered: {rendered}"
    );
    assert!(
        rendered.contains("    if ((loc2 == 3)) {") && rendered.contains("    } else {"),
        "nested if/else recovered one level deeper than the loop: {rendered}"
    );
    assert!(
        rendered.contains("        loc2 = (loc2 + 10);")
            && rendered.contains("        loc2 = (loc2 + 1);"),
        "both nested arms keep their bodies at the deepest indent: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains(&format!("L{top_off}:")),
        "a fully reducible loop+if/else must leave no goto/label residue: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "nested structuring drops nothing: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn lifts_global_slot_access_with_resolved_trait_name() {
    let mut get_code: Vec<u8> = vec![0x6E];
    u30(5, &mut get_code);
    get_code.push(0x48);
    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "counter", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        vec![slot_trait(3, 5)],
        one_param_method(),
        get_code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return global.counter;"),
        "getglobalslot must read off the global object with the resolved trait name: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "getglobalslot must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );

    let mut set_code: Vec<u8> = vec![0xD1, 0x6F];
    u30(5, &mut set_code);
    set_code.push(0x47);
    let abc2: AbcFile = mk_abc(
        &["", "C", "Object", "counter", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        vec![slot_trait(3, 5)],
        one_param_method(),
        set_code,
    );
    let (rendered2, lifted2): (String, LiftedBody) = lift_only(&abc2);
    assert!(
        rendered2.contains("global.counter = arg1;"),
        "setglobalslot must assign to the global object slot: {rendered2}"
    );
    assert!(
        lifted2.structurally_recovered,
        "setglobalslot must be modelled, not dropped: {:?}",
        lifted2.fidelity_warning()
    );
}

#[test]
fn lifts_pushnamespace_with_uri() {
    let mut abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run", "http://ns.example/2024"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        Vec::new(),
    );
    let ns_idx: u32 = abc.cpool.namespaces.len() as u32;
    abc.cpool.namespaces.push(Namespace {
        kind: 0x08,
        name_index: 5,
    });
    let mut code: Vec<u8> = vec![0x31];
    u30(ns_idx, &mut code);
    code.push(0x48);
    let abc: AbcFile = AbcFile {
        method_bodies: vec![MethodBody {
            method: abc.method_bodies[0].method,
            max_stack: 8,
            local_count: 8,
            init_scope_depth: 0,
            max_scope_depth: 1,
            code,
            exceptions: Vec::new(),
            traits: Vec::new(),
        }],
        ..abc
    };
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("return new Namespace(\"http://ns.example/2024\");"),
        "pushnamespace must materialize the namespace uri, not drop it: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "pushnamespace must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
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
        lifted.structurally_recovered,
        "for-in primitives must be modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
}

fn patch_branch(code: &mut [u8], operand_at: usize, after: usize, target: usize) {
    let rel: i32 = target as i32 - after as i32;
    let raw: u32 = rel as u32;
    code[operand_at] = (raw & 0xFF) as u8;
    code[operand_at + 1] = ((raw >> 8) & 0xFF) as u8;
    code[operand_at + 2] = ((raw >> 16) & 0xFF) as u8;
}

#[test]
fn structures_for_each_iterator_loop_into_for_each_block() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = Vec::new();
    code.push(0x24);
    code.push(0x00);
    code.push(0xD6);
    let jump_at: usize = code.len();
    code.push(0x10);
    let jump_operand: usize = code.len();
    s24(0, &mut code);
    let after_jump: usize = code.len();
    let top_off: usize = code.len();
    code.push(0xD1);
    code.push(0xD2);
    code.push(0x23);
    code.push(0x82);
    code.push(0xD7);
    code.push(0xD3);
    code.push(0x63);
    code.push(0x04);
    let test_off: usize = code.len();
    code.push(0x32);
    code.push(0x01);
    code.push(0x02);
    let iftrue_at: usize = code.len();
    code.push(0x11);
    let iftrue_operand: usize = code.len();
    s24(0, &mut code);
    let after_iftrue: usize = code.len();
    code.push(0x47);
    let _ = (jump_at, iftrue_at);
    patch_branch(&mut code, jump_operand, after_jump, test_off);
    patch_branch(&mut code, iftrue_operand, after_iftrue, top_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "items", "scan"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let foreach: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::ForEach { .. }))
        .expect("hasnext2/nextvalue loop must fold into a for each block");
    let Stmt::ForEach {
        var,
        collection,
        body,
    } = foreach
    else {
        unreachable!()
    };
    assert_eq!(body.len(), 1, "for-each body holds the single assignment");
    let _ = (var, collection);
    assert!(
        rendered.contains("for each (var loc3 in arg1) {"),
        "for-each header names the loop var and the collection: {rendered}"
    );
    assert!(
        rendered.contains("loc4 = loc3;"),
        "for-each body is preserved: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains("while") && !rendered.contains("hasNext"),
        "the iterator scaffolding must be fully consumed: {rendered}"
    );
    assert!(
        lifted.structurally_recovered && lifted.fully_structured,
        "for-each lift drops nothing and leaves no residual graph: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn structures_for_in_iterator_loop_into_for_in_block() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = vec![0x24, 0x00, 0xD6, 0x10];
    let jump_operand: usize = code.len();
    s24(0, &mut code);
    let after_jump: usize = code.len();
    let top_off: usize = code.len();
    code.push(0xD1);
    code.push(0xD2);
    code.push(0x1E);
    code.push(0xD7);
    code.push(0xD3);
    code.push(0x63);
    code.push(0x04);
    let test_off: usize = code.len();
    code.push(0x32);
    code.push(0x01);
    code.push(0x02);
    code.push(0x11);
    let iftrue_operand: usize = code.len();
    s24(0, &mut code);
    let after_iftrue: usize = code.len();
    code.push(0x47);
    patch_branch(&mut code, jump_operand, after_jump, test_off);
    patch_branch(&mut code, iftrue_operand, after_iftrue, top_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "items", "keys"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    assert!(
        lifted
            .statements
            .iter()
            .any(|s: &Stmt| matches!(s, Stmt::ForIn { .. })),
        "hasnext2/nextname loop must fold into a for-in block: {rendered}"
    );
    assert!(
        rendered.contains("for (var loc3 in arg1) {"),
        "for-in header names the loop var and the collection: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains("while") && !rendered.contains("hasNext"),
        "the iterator scaffolding must be fully consumed: {rendered}"
    );
    assert!(
        lifted.structurally_recovered && lifted.fully_structured,
        "for-in lift drops nothing: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn structures_counted_loop_into_c_style_for() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = vec![0x24, 0x00, 0xD6, 0x10];
    let jump_operand: usize = code.len();
    s24(0, &mut code);
    let after_jump: usize = code.len();
    let top_off: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x01);
    code.push(0xA0);
    code.push(0x63);
    code.push(0x03);
    code.push(0xD2);
    code.push(0x24);
    code.push(0x01);
    code.push(0xA0);
    code.push(0xD6);
    let test_off: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x0A);
    code.push(0x15);
    let iftrue_operand: usize = code.len();
    s24(0, &mut code);
    let after_iftrue: usize = code.len();
    code.push(0x47);
    patch_branch(&mut code, jump_operand, after_jump, test_off);
    patch_branch(&mut code, iftrue_operand, after_iftrue, top_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "acc", "loop"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let for_stmt: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::For { .. }))
        .expect("init + back-edge test + trailing update must fold into a C-style for");
    let Stmt::For { body, .. } = for_stmt else {
        unreachable!()
    };
    assert_eq!(body.len(), 1, "the loop body is the single accumulate stmt");
    assert!(
        rendered.contains("for (loc2 = 0; (loc2 < 10); loc2 = (loc2 + 1)) {"),
        "C-style for must reconstruct init, condition and update in the header: {rendered}"
    );
    assert!(
        rendered.contains("loc3 = (loc2 + 1);"),
        "the loop body assignment survives: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains("while"),
        "a counted loop must not fall back to while/goto: {rendered}"
    );
    assert!(
        lifted.structurally_recovered && lifted.fully_structured,
        "counted-for lift is fully structured: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn structures_if_else_diamond_into_nested_blocks() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = Vec::new();
    code.push(0xD1);
    code.push(0x24);
    code.push(0x00);
    let ifne_at: usize = code.len();
    code.push(0x14);
    let ifne_operand: usize = code.len();
    s24(0, &mut code);
    let after_ifne: usize = code.len();
    code.push(0x24);
    code.push(0x0A);
    code.push(0xD6);
    let jump_at: usize = code.len();
    code.push(0x10);
    let jump_operand: usize = code.len();
    s24(0, &mut code);
    let after_jump: usize = code.len();
    let else_off: usize = code.len();
    code.push(0x24);
    code.push(0x14);
    code.push(0xD6);
    let end_off: usize = code.len();
    code.push(0xD2);
    code.push(0x48);
    let _ = ifne_at;
    let _ = jump_at;
    patch_branch(&mut code, ifne_operand, after_ifne, else_off);
    patch_branch(&mut code, jump_operand, after_jump, end_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "pick"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let if_else: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::IfElse { .. }))
        .expect("the forward branch plus skip-jump must fold into one if/else");
    let Stmt::IfElse {
        then_body,
        else_body,
        ..
    } = if_else
    else {
        unreachable!()
    };
    assert_eq!(then_body.len(), 1, "then arm holds one assignment");
    assert_eq!(else_body.len(), 1, "else arm holds one assignment");

    assert!(
        rendered.contains("if ((arg1 == 0)) {"),
        "ifne skip must negate to == and open the if arm: {rendered}"
    );
    assert!(
        rendered.contains("} else {"),
        "the skip-jump must produce a structured else arm: {rendered}"
    );
    assert!(
        rendered.contains("loc2 = 10;") && rendered.contains("loc2 = 20;"),
        "both arms keep their real bodies: {rendered}"
    );
    assert!(
        rendered.contains("return loc2;"),
        "the merge continuation after the diamond must remain: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains("L0:"),
        "a reducible if/else must leave no goto/label residue: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "if/else lift drops nothing: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn models_pushwith_as_with_block_and_resolves_findproperty() {
    use disrobe_pass_as3::lifter::{Expr, Stmt};

    let mut code: Vec<u8> = vec![0xD1, 0x1C];
    code.push(0x5D);
    u30(3, &mut code);
    code.push(0x24);
    code.push(0x05);
    code.push(0x61);
    u30(3, &mut code);
    code.push(0x1D);
    code.push(0x47);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let with_stmt: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::With { .. }))
        .expect("pushwith must open a structured with block, not be dropped");
    let Stmt::With { object, body } = with_stmt else {
        unreachable!()
    };
    assert_eq!(
        *object,
        Expr::Local(1),
        "the with object is the pushed scope value (the parameter local)"
    );
    assert_eq!(body.len(), 1, "the with body holds the single assignment");

    assert!(
        rendered.contains("with (arg1) {"),
        "pushwith must materialize a with block on its scope object: {rendered}"
    );
    assert!(
        rendered.contains("    arg1.x = 5;"),
        "findpropstrict inside the with must resolve x against the with object: {rendered}"
    );
    assert!(
        !rendered.contains("    x = 5;"),
        "the lexical scope-object shorthand must not leak inside a with: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "pushwith/popscope/findpropstrict are modelled, not dropped: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn findproperty_without_with_stays_lexical_call() {
    let mut code: Vec<u8> = vec![0xD0, 0x30];
    code.push(0x5D);
    u30(4, &mut code);
    code.push(0x4F);
    u30(4, &mut code);
    u30(0, &mut code);
    code.push(0x47);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "run"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);
    assert!(
        rendered.contains("run();"),
        "with no with scope, a findpropstrict call stays an unqualified lexical call: {rendered}"
    );
    assert!(
        !rendered.contains("with ("),
        "a plain pushscope must not synthesize a with block: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "plain pushscope plus lexical call drops nothing: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn structures_do_while_back_edge_into_do_loop() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = Vec::new();
    code.push(0x24);
    code.push(0x00);
    code.push(0xD6);
    let top_off: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x01);
    code.push(0xA0);
    code.push(0xD6);
    code.push(0xD2);
    code.push(0xD1);
    code.push(0x0F);
    let back_operand: usize = code.len();
    s24(0, &mut code);
    let after_back: usize = code.len();
    code.push(0xD2);
    code.push(0x48);
    patch_branch(&mut code, back_operand, after_back, top_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "loop"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let do_while: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::DoWhile { .. }))
        .expect("a bottom-test back-edge with no entry jump must fold into a do/while");
    let Stmt::DoWhile { body, .. } = do_while else {
        unreachable!()
    };
    assert!(
        body.iter().any(|s: &Stmt| matches!(s, Stmt::Assign { .. })),
        "do/while body retains its increment: {body:?}"
    );

    assert!(
        rendered.contains("do {"),
        "back-edge must open a do block: {rendered}"
    );
    assert!(
        rendered.contains("} while ((loc2 < arg1));"),
        "the back-edge condition becomes the do/while continuation: {rendered}"
    );
    assert!(
        rendered.contains("loc2 = (loc2 + 1);"),
        "the loop body must be recovered inside the do block: {rendered}"
    );
    assert!(
        rendered.contains("return loc2;"),
        "the post-loop continuation must remain: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains(&format!("L{top_off}:")),
        "a reducible do/while must leave no goto/label residue: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "do/while lift drops nothing: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn structures_while_with_conditional_break_into_break_statement() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = vec![0x24, 0x00, 0xD6];
    code.push(0x10);
    let entry_operand: usize = code.len();
    s24(0, &mut code);
    let after_entry: usize = code.len();

    let top_off: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x05);
    code.push(0x14);
    let break_operand: usize = code.len();
    s24(0, &mut code);
    let after_break: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x01);
    code.push(0xA0);
    code.push(0xD6);

    let test_off: usize = code.len();
    code.push(0xD2);
    code.push(0xD1);
    code.push(0x0F);
    let back_operand: usize = code.len();
    s24(0, &mut code);
    let after_back: usize = code.len();

    let merge_off: usize = code.len();
    code.push(0xD2);
    code.push(0x48);

    patch_branch(&mut code, entry_operand, after_entry, test_off);
    patch_branch(&mut code, break_operand, after_break, merge_off);
    patch_branch(&mut code, back_operand, after_back, top_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "loop"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let while_stmt: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::While { .. }))
        .expect("a top-test loop with an early-exit branch must fold into a while");
    let Stmt::While { body, .. } = while_stmt else {
        unreachable!()
    };
    assert!(
        body.iter().any(|s: &Stmt| matches!(
            s,
            Stmt::IfBlock { body, .. } if body.iter().any(|b: &Stmt| matches!(b, Stmt::Break))
        )),
        "the forward exit branch must lower into a guarded break, not residual goto: {body:?}"
    );
    assert!(
        rendered.contains("while ((loc2 < arg1)) {"),
        "while header recovered: {rendered}"
    );
    assert!(
        rendered.contains("break;"),
        "the early-exit edge must render as a break: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains(&format!("L{merge_off}:")),
        "a while+break must leave no goto/label residue: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "while+break lift drops nothing: {:?}",
        lifted.fidelity_warning()
    );
}

#[test]
fn structures_while_with_conditional_continue_into_continue_statement() {
    use disrobe_pass_as3::lifter::Stmt;

    let mut code: Vec<u8> = vec![0x24, 0x00, 0xD6];
    code.push(0x10);
    let entry_operand: usize = code.len();
    s24(0, &mut code);
    let after_entry: usize = code.len();

    let top_off: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x01);
    code.push(0xA0);
    code.push(0xD6);
    code.push(0xD2);
    code.push(0x24);
    code.push(0x07);
    code.push(0x14);
    let continue_operand: usize = code.len();
    s24(0, &mut code);
    let after_continue: usize = code.len();
    code.push(0xD2);
    code.push(0x24);
    code.push(0x02);
    code.push(0xA0);
    code.push(0xD6);

    let test_off: usize = code.len();
    code.push(0xD2);
    code.push(0xD1);
    code.push(0x0F);
    let back_operand: usize = code.len();
    s24(0, &mut code);
    let after_back: usize = code.len();
    code.push(0xD2);
    code.push(0x48);

    patch_branch(&mut code, entry_operand, after_entry, test_off);
    patch_branch(&mut code, continue_operand, after_continue, test_off);
    patch_branch(&mut code, back_operand, after_back, top_off);

    let abc: AbcFile = mk_abc(
        &["", "C", "Object", "x", "loop"],
        &[(1, 1), (1, 2), (1, 3), (1, 4)],
        Vec::new(),
        one_param_method(),
        code,
    );
    let (rendered, lifted): (String, LiftedBody) = lift_only(&abc);

    let while_stmt: &Stmt = lifted
        .statements
        .iter()
        .find(|s: &&Stmt| matches!(s, Stmt::While { .. }))
        .expect("a top-test loop with a back-jump to the test must fold into a while");
    let Stmt::While { body, .. } = while_stmt else {
        unreachable!()
    };
    assert!(
        body.iter().any(|s: &Stmt| matches!(
            s,
            Stmt::IfBlock { body, .. } if body.iter().any(|b: &Stmt| matches!(b, Stmt::Continue))
        )),
        "the jump back to the test must lower into a guarded continue: {body:?}"
    );
    assert!(
        rendered.contains("continue;"),
        "the loop-test back edge must render as a continue: {rendered}"
    );
    assert!(
        !rendered.contains("goto") && !rendered.contains(&format!("L{top_off}:")),
        "a while+continue must leave no goto/label residue: {rendered}"
    );
    assert!(
        lifted.structurally_recovered,
        "while+continue lift drops nothing: {:?}",
        lifted.fidelity_warning()
    );
}
