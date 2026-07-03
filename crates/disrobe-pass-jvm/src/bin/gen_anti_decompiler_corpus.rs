#![allow(
    clippy::print_stdout,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

use std::fs::File;
use std::io::Write as _;
use std::path::PathBuf;

struct Cp {
    bytes: Vec<u8>,
    count: u16,
}

impl Cp {
    const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            count: 1,
        }
    }
    const fn idx(&mut self) -> u16 {
        let i: u16 = self.count;
        self.count += 1;
        i
    }
    fn utf8(&mut self, s: &str) -> u16 {
        let i: u16 = self.idx();
        self.bytes.push(1);
        self.bytes
            .extend_from_slice(&(s.len() as u16).to_be_bytes());
        self.bytes.extend_from_slice(s.as_bytes());
        i
    }
    fn class(&mut self, name_idx: u16) -> u16 {
        let i: u16 = self.idx();
        self.bytes.push(7);
        self.bytes.extend_from_slice(&name_idx.to_be_bytes());
        i
    }
    fn nat(&mut self, n: u16, t: u16) -> u16 {
        let i: u16 = self.idx();
        self.bytes.push(12);
        self.bytes.extend_from_slice(&n.to_be_bytes());
        self.bytes.extend_from_slice(&t.to_be_bytes());
        i
    }
    fn methodref(&mut self, cls: u16, nat: u16) -> u16 {
        let i: u16 = self.idx();
        self.bytes.push(10);
        self.bytes.extend_from_slice(&cls.to_be_bytes());
        self.bytes.extend_from_slice(&nat.to_be_bytes());
        i
    }
    fn fieldref(&mut self, cls: u16, nat: u16) -> u16 {
        let i: u16 = self.idx();
        self.bytes.push(9);
        self.bytes.extend_from_slice(&cls.to_be_bytes());
        self.bytes.extend_from_slice(&nat.to_be_bytes());
        i
    }
    fn string(&mut self, u: u16) -> u16 {
        let i: u16 = self.idx();
        self.bytes.push(8);
        self.bytes.extend_from_slice(&u.to_be_bytes());
        i
    }
}

struct Std {
    sys_out: u16,
    ps_println: u16,
    sb_cls: u16,
    sb_init: u16,
    sb_append_str: u16,
    sb_append_int: u16,
    sb_tostr: u16,
}

fn intern_std(cp: &mut Cp) -> Std {
    let sys_name: u16 = cp.utf8("java/lang/System");
    let sys_cls: u16 = cp.class(sys_name);
    let out_n: u16 = cp.utf8("out");
    let ps_d: u16 = cp.utf8("Ljava/io/PrintStream;");
    let out_nat: u16 = cp.nat(out_n, ps_d);
    let sys_out: u16 = cp.fieldref(sys_cls, out_nat);

    let ps_name: u16 = cp.utf8("java/io/PrintStream");
    let ps_cls: u16 = cp.class(ps_name);
    let println_n: u16 = cp.utf8("println");
    let println_d: u16 = cp.utf8("(Ljava/lang/String;)V");
    let println_nat: u16 = cp.nat(println_n, println_d);
    let ps_println: u16 = cp.methodref(ps_cls, println_nat);

    let sb_name: u16 = cp.utf8("java/lang/StringBuilder");
    let sb_cls: u16 = cp.class(sb_name);
    let init_n: u16 = cp.utf8("<init>");
    let void_d: u16 = cp.utf8("()V");
    let sb_init_nat: u16 = cp.nat(init_n, void_d);
    let sb_init: u16 = cp.methodref(sb_cls, sb_init_nat);
    let append_n: u16 = cp.utf8("append");
    let append_str_d: u16 = cp.utf8("(Ljava/lang/String;)Ljava/lang/StringBuilder;");
    let append_str_nat: u16 = cp.nat(append_n, append_str_d);
    let sb_append_str: u16 = cp.methodref(sb_cls, append_str_nat);
    let append_int_d: u16 = cp.utf8("(I)Ljava/lang/StringBuilder;");
    let append_int_nat: u16 = cp.nat(append_n, append_int_d);
    let sb_append_int: u16 = cp.methodref(sb_cls, append_int_nat);
    let tostr_n: u16 = cp.utf8("toString");
    let tostr_d: u16 = cp.utf8("()Ljava/lang/String;");
    let tostr_nat: u16 = cp.nat(tostr_n, tostr_d);
    let sb_tostr: u16 = cp.methodref(sb_cls, tostr_nat);

    Std {
        sys_out,
        ps_println,
        sb_cls,
        sb_init,
        sb_append_str,
        sb_append_int,
        sb_tostr,
    }
}

fn print_label(c: &mut Vec<u8>, s: &Std, label_str: u16, var: u8) {
    c.push(0xb2);
    c.extend_from_slice(&s.sys_out.to_be_bytes());
    c.push(0xbb);
    c.extend_from_slice(&s.sb_cls.to_be_bytes());
    c.push(0x59);
    c.push(0xb7);
    c.extend_from_slice(&s.sb_init.to_be_bytes());
    c.push(0x13);
    c.extend_from_slice(&label_str.to_be_bytes());
    c.push(0xb6);
    c.extend_from_slice(&s.sb_append_str.to_be_bytes());
    c.push(0x15);
    c.push(var);
    c.push(0xb6);
    c.extend_from_slice(&s.sb_append_int.to_be_bytes());
    c.push(0xb6);
    c.extend_from_slice(&s.sb_tostr.to_be_bytes());
    c.push(0xb6);
    c.extend_from_slice(&s.ps_println.to_be_bytes());
}

fn emit_method(
    access: u16,
    name: u16,
    desc: u16,
    code_attr: u16,
    max_stack: u16,
    max_locals: u16,
    code: &[u8],
    smt: &[u8],
) -> Vec<u8> {
    let mut m: Vec<u8> = Vec::new();
    m.extend_from_slice(&access.to_be_bytes());
    m.extend_from_slice(&name.to_be_bytes());
    m.extend_from_slice(&desc.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&max_stack.to_be_bytes());
    body.extend_from_slice(&max_locals.to_be_bytes());
    body.extend_from_slice(&(code.len() as u32).to_be_bytes());
    body.extend_from_slice(code);
    body.extend_from_slice(&0u16.to_be_bytes());
    let attr_count: u16 = u16::from(!smt.is_empty());
    body.extend_from_slice(&attr_count.to_be_bytes());
    body.extend_from_slice(smt);
    m.extend_from_slice(&code_attr.to_be_bytes());
    m.extend_from_slice(&(body.len() as u32).to_be_bytes());
    m.extend_from_slice(&body);
    m
}

fn class_header(major: u16, cp: &Cp, this_cls: u16, obj_cls: u16, methods: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&major.to_be_bytes());
    out.extend_from_slice(&cp.count.to_be_bytes());
    out.extend_from_slice(&cp.bytes);
    out.extend_from_slice(&0x0021u16.to_be_bytes());
    out.extend_from_slice(&this_cls.to_be_bytes());
    out.extend_from_slice(&obj_cls.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&3u16.to_be_bytes());
    out.extend_from_slice(methods);
    out.extend_from_slice(&0u16.to_be_bytes());
    out
}

fn build_jsr_finally() -> Vec<u8> {
    let mut cp: Cp = Cp::new();
    let this_name: u16 = cp.utf8("JsrFinally");
    let this_cls: u16 = cp.class(this_name);
    let obj_name: u16 = cp.utf8("java/lang/Object");
    let obj_cls: u16 = cp.class(obj_name);
    let init_n: u16 = cp.utf8("<init>");
    let void_d: u16 = cp.utf8("()V");
    let init_nat: u16 = cp.nat(init_n, void_d);
    let obj_init: u16 = cp.methodref(obj_cls, init_nat);
    let code_attr: u16 = cp.utf8("Code");

    let twice_n: u16 = cp.utf8("twice");
    let twice_d: u16 = cp.utf8("(I)I");
    let main_n: u16 = cp.utf8("main");
    let main_d: u16 = cp.utf8("([Ljava/lang/String;)V");

    let s: Std = intern_std(&mut cp);
    let s_a: u16 = cp.utf8("a=");
    let s_a_str: u16 = cp.string(s_a);
    let s_b: u16 = cp.utf8("b=");
    let s_b_str: u16 = cp.string(s_b);
    let s_sum: u16 = cp.utf8("sum=");
    let s_sum_str: u16 = cp.string(s_sum);

    let twice_nat: u16 = cp.nat(twice_n, twice_d);
    let twice_ref: u16 = cp.methodref(this_cls, twice_nat);

    let mut methods: Vec<u8> = Vec::new();
    let init_code: Vec<u8> = vec![0x2a, 0xb7, (obj_init >> 8) as u8, obj_init as u8, 0xb1];
    methods.extend_from_slice(&emit_method(
        0x0001,
        init_n,
        void_d,
        code_attr,
        1,
        1,
        &init_code,
        &[],
    ));

    let mut twice_code: Vec<u8> = Vec::new();
    let sub_off: i16 = 8;
    twice_code.push(0xa8);
    twice_code.extend_from_slice(&sub_off.to_be_bytes());
    twice_code.push(0x1b);
    twice_code.push(0xac);
    twice_code.push(0x00);
    twice_code.push(0x00);
    twice_code.push(0x00);
    twice_code.push(0x3a);
    twice_code.push(2);
    twice_code.push(0x1a);
    twice_code.push(0x1a);
    twice_code.push(0x60);
    twice_code.push(0x3c);
    twice_code.push(0xa9);
    twice_code.push(2);
    methods.extend_from_slice(&emit_method(
        0x0008,
        twice_n,
        twice_d,
        code_attr,
        2,
        3,
        &twice_code,
        &[],
    ));

    let mut main_code: Vec<u8> = vec![0x10, 7, 0xb8];
    main_code.extend_from_slice(&twice_ref.to_be_bytes());
    main_code.push(0x3c);
    main_code.push(0x10);
    main_code.push(20);
    main_code.push(0xb8);
    main_code.extend_from_slice(&twice_ref.to_be_bytes());
    main_code.push(0x3d);
    print_label(&mut main_code, &s, s_a_str, 1);
    print_label(&mut main_code, &s, s_b_str, 2);
    main_code.push(0xb2);
    main_code.extend_from_slice(&s.sys_out.to_be_bytes());
    main_code.push(0xbb);
    main_code.extend_from_slice(&s.sb_cls.to_be_bytes());
    main_code.push(0x59);
    main_code.push(0xb7);
    main_code.extend_from_slice(&s.sb_init.to_be_bytes());
    main_code.push(0x13);
    main_code.extend_from_slice(&s_sum_str.to_be_bytes());
    main_code.push(0xb6);
    main_code.extend_from_slice(&s.sb_append_str.to_be_bytes());
    main_code.push(0x1b);
    main_code.push(0x1c);
    main_code.push(0x60);
    main_code.push(0xb6);
    main_code.extend_from_slice(&s.sb_append_int.to_be_bytes());
    main_code.push(0xb6);
    main_code.extend_from_slice(&s.sb_tostr.to_be_bytes());
    main_code.push(0xb6);
    main_code.extend_from_slice(&s.ps_println.to_be_bytes());
    main_code.push(0xb1);
    methods.extend_from_slice(&emit_method(
        0x0009,
        main_n,
        main_d,
        code_attr,
        5,
        3,
        &main_code,
        &[],
    ));

    class_header(49, &cp, this_cls, obj_cls, &methods)
}

fn build_bad_frames() -> Vec<u8> {
    let mut cp: Cp = Cp::new();
    let this_name: u16 = cp.utf8("BadFrames");
    let this_cls: u16 = cp.class(this_name);
    let obj_name: u16 = cp.utf8("java/lang/Object");
    let obj_cls: u16 = cp.class(obj_name);
    let init_n: u16 = cp.utf8("<init>");
    let void_d: u16 = cp.utf8("()V");
    let init_nat: u16 = cp.nat(init_n, void_d);
    let obj_init: u16 = cp.methodref(obj_cls, init_nat);
    let code_attr: u16 = cp.utf8("Code");
    let smt_name: u16 = cp.utf8("StackMapTable");

    let pick_n: u16 = cp.utf8("pick");
    let pick_d: u16 = cp.utf8("(I)I");
    let main_n: u16 = cp.utf8("main");
    let main_d: u16 = cp.utf8("([Ljava/lang/String;)V");

    let s: Std = intern_std(&mut cp);
    let s_lo: u16 = cp.utf8("lo=");
    let s_lo_str: u16 = cp.string(s_lo);
    let s_hi: u16 = cp.utf8("hi=");
    let s_hi_str: u16 = cp.string(s_hi);

    let pick_nat: u16 = cp.nat(pick_n, pick_d);
    let pick_ref: u16 = cp.methodref(this_cls, pick_nat);

    let mut methods: Vec<u8> = Vec::new();
    let init_code: Vec<u8> = vec![0x2a, 0xb7, (obj_init >> 8) as u8, obj_init as u8, 0xb1];
    methods.extend_from_slice(&emit_method(
        0x0001,
        init_n,
        void_d,
        code_attr,
        1,
        1,
        &init_code,
        &[],
    ));

    let mut pick_code: Vec<u8> = vec![0x1a, 0x10, 10, 0xa2];
    pick_code.extend_from_slice(&7i16.to_be_bytes());
    pick_code.push(0x11);
    pick_code.extend_from_slice(&100i16.to_be_bytes());
    pick_code.push(0xac);
    pick_code.push(0x11);
    pick_code.extend_from_slice(&200i16.to_be_bytes());
    pick_code.push(0xac);
    let stray_frame_type: u8 = 5;
    let mut smt_body: Vec<u8> = Vec::new();
    smt_body.extend_from_slice(&1u16.to_be_bytes());
    smt_body.push(stray_frame_type);
    let mut smt: Vec<u8> = Vec::new();
    smt.extend_from_slice(&smt_name.to_be_bytes());
    smt.extend_from_slice(&(smt_body.len() as u32).to_be_bytes());
    smt.extend_from_slice(&smt_body);
    methods.extend_from_slice(&emit_method(
        0x0008, pick_n, pick_d, code_attr, 2, 1, &pick_code, &smt,
    ));

    let mut main_code: Vec<u8> = vec![0x10, 3, 0xb8];
    main_code.extend_from_slice(&pick_ref.to_be_bytes());
    main_code.push(0x3c);
    main_code.push(0x10);
    main_code.push(50);
    main_code.push(0xb8);
    main_code.extend_from_slice(&pick_ref.to_be_bytes());
    main_code.push(0x3d);
    print_label(&mut main_code, &s, s_lo_str, 1);
    print_label(&mut main_code, &s, s_hi_str, 2);
    main_code.push(0xb1);
    methods.extend_from_slice(&emit_method(
        0x0009,
        main_n,
        main_d,
        code_attr,
        5,
        3,
        &main_code,
        &[],
    ));

    class_header(50, &cp, this_cls, obj_cls, &methods)
}

fn main() -> std::io::Result<()> {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.pop();
    dir.push("corpus");
    dir.push("jvm");
    dir.push("antidecompiler");
    std::fs::create_dir_all(&dir)?;

    let jsr: Vec<u8> = build_jsr_finally();
    let jsr_path: PathBuf = dir.join("JsrFinally.class");
    File::create(&jsr_path)?.write_all(&jsr)?;
    println!("wrote {} ({} bytes)", jsr_path.display(), jsr.len());

    let bad: Vec<u8> = build_bad_frames();
    let bad_path: PathBuf = dir.join("BadFrames.class");
    File::create(&bad_path)?.write_all(&bad)?;
    println!("wrote {} ({} bytes)", bad_path.display(), bad.len());

    Ok(())
}
