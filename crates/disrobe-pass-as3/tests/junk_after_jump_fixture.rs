#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_as3::abc::{
    self, AbcFile, ClassInfo, DisasmLine, ExceptionInfo, MethodBody, MethodInfo, TraitInfo, disasm,
};
use disrobe_pass_as3::lifter::{LiftedBody, LocalNames, lift_body, local_names_for, render_body};
use disrobe_pass_as3::swf::{self, DoAbc, Swf};

const CLASS_NAME: &str = "JunkAfterJump";
const METHOD_NAME: &str = "pick";
const HAXE_SOURCE: &str = include_str!("fixtures/JunkAfterJump.hx");
const PROVENANCE: &str = include_str!("fixtures/junk_after_jump.provenance");
const SWF_BYTES: &[u8] = include_bytes!("fixtures/junk_after_jump.swf");
const EXPECTED_PROVENANCE: &str = "compiler=haxe 4.3.7\ncommand=haxe -cp crates/disrobe-pass-as3/tests/fixtures -main JunkAfterJump -swf crates/disrobe-pass-as3/tests/fixtures/junk_after_jump.swf\ngenerated=2026-09-28\n";
const OP_JUMP: u8 = 0x10;
const OP_LOOKUPSWITCH: u8 = 0x1B;
const OP_PUSHBYTE: u8 = 0x24;

fn parse_fixture() -> AbcFile {
    assert!(
        HAXE_SOURCE.contains("static function pick(n:Int):Int"),
        "the authored source changed; rebuild and revalidate the committed fixture"
    );
    assert_eq!(
        PROVENANCE, EXPECTED_PROVENANCE,
        "the compiler provenance changed; rebuild and revalidate the committed fixture"
    );
    let swf: Swf = swf::parse(SWF_BYTES).expect("the committed Haxe SWF must parse");
    let blocks: Vec<DoAbc> = swf.collect_do_abc();
    assert_eq!(
        blocks.len(),
        1,
        "the compiler fixture carries one ABC payload"
    );
    abc::parse(&blocks[0].abc_bytes).expect("the committed Haxe ABC must parse")
}

fn target_method(abc: &AbcFile) -> (usize, MethodInfo) {
    let class_index: usize = abc
        .instances
        .iter()
        .position(|instance| {
            abc.cpool
                .render_multiname(instance.name_index)
                .is_ok_and(|name: String| name == CLASS_NAME)
        })
        .expect("the fixture defines the class");
    let class: &ClassInfo = &abc.classes[class_index];
    let method: &TraitInfo = class
        .traits
        .iter()
        .filter(|trait_info| trait_info.kind & 0x0F == 1)
        .find(|trait_info| {
            abc.cpool
                .render_multiname_property(trait_info.name_index)
                .is_ok_and(|name: String| name == METHOD_NAME)
        })
        .expect("the fixture exposes the static method");
    let body_index: usize = abc
        .method_bodies
        .iter()
        .position(|body| body.method == method.method_index)
        .expect("the static method has a body");
    let info: MethodInfo = abc.methods[usize::try_from(method.method_index).unwrap()].clone();
    (body_index, info)
}

fn read_s24(code: &[u8], at: usize) -> i64 {
    let raw: u32 =
        u32::from(code[at]) | (u32::from(code[at + 1]) << 8) | (u32::from(code[at + 2]) << 16);
    let signed: i32 = ((raw << 8) as i32) >> 8;
    i64::from(signed)
}

fn write_s24(code: &mut [u8], at: usize, value: i64) {
    let raw: u32 = i32::try_from(value).expect("branch offset fits in s24") as u32;
    code[at] = (raw & 0xFF) as u8;
    code[at + 1] = ((raw >> 8) & 0xFF) as u8;
    code[at + 2] = ((raw >> 16) & 0xFF) as u8;
}

const fn shifted(position: usize, inserted_at: usize) -> usize {
    if position >= inserted_at {
        position + 1
    } else {
        position
    }
}

fn insert_junk_after_first_jump(body: &MethodBody) -> MethodBody {
    let lines: Vec<DisasmLine> = disasm(&body.code).expect("the compiler output disassembles");
    assert!(
        lines.iter().all(|line| line.opcode != OP_LOOKUPSWITCH),
        "the fixture method must stay switch-free so only s24 branches need retargeting"
    );
    let jump: &DisasmLine = lines
        .iter()
        .find(|line| line.opcode == OP_JUMP)
        .expect("the compiler emits an unconditional jump for the loop");
    let inserted_at: usize = jump.offset + 4;
    let mut code: Vec<u8> = Vec::with_capacity(body.code.len() + 1);
    code.extend_from_slice(&body.code[..inserted_at]);
    code.push(OP_PUSHBYTE);
    code.extend_from_slice(&body.code[inserted_at..]);
    for line in &lines {
        if !(0x0C..=0x1A).contains(&line.opcode) {
            continue;
        }
        let old_end: usize = line.offset + 4;
        let old_target: i64 =
            i64::try_from(old_end).unwrap() + read_s24(&body.code, line.offset + 1);
        let new_offset: usize = shifted(line.offset, inserted_at);
        let new_target: usize = shifted(usize::try_from(old_target).unwrap(), inserted_at);
        let relative: i64 =
            i64::try_from(new_target).unwrap() - i64::try_from(new_offset + 4).unwrap();
        write_s24(&mut code, new_offset + 1, relative);
    }
    let exceptions: Vec<ExceptionInfo> = body
        .exceptions
        .iter()
        .map(|handler: &ExceptionInfo| {
            let mut moved: ExceptionInfo = handler.clone();
            moved.from = u32::try_from(shifted(handler.from as usize, inserted_at)).unwrap();
            moved.to = u32::try_from(shifted(handler.to as usize, inserted_at)).unwrap();
            moved.target = u32::try_from(shifted(handler.target as usize, inserted_at)).unwrap();
            moved
        })
        .collect();
    MethodBody {
        code,
        exceptions,
        ..body.clone()
    }
}

fn rendered(abc: &AbcFile, body: &MethodBody, info: &MethodInfo) -> Result<String, String> {
    let names: LocalNames = local_names_for(abc, Some(info));
    lift_body(abc, body, Some(info))
        .map(|lifted: LiftedBody| render_body(&lifted, &names, ""))
        .map_err(|error| error.to_string())
}

#[test]
fn a_junk_byte_after_a_compiled_jump_lifts_the_same_body_or_is_refused() {
    let abc: AbcFile = parse_fixture();
    let (body_index, info): (usize, MethodInfo) = target_method(&abc);
    let original: &MethodBody = &abc.method_bodies[body_index];
    let clean: String = rendered(&abc, original, &info).expect("the compiler output lifts");
    assert!(
        clean.contains("return") && clean.lines().count() > 3,
        "the unmodified method must lift to a real body: {clean}"
    );
    let junked: MethodBody = insert_junk_after_first_jump(original);
    assert_eq!(junked.code.len(), original.code.len() + 1);
    match rendered(&abc, &junked, &info) {
        Ok(text) => assert_eq!(
            text, clean,
            "an unreachable byte after a jump must not change the lifted body"
        ),
        Err(error) => assert!(
            error.starts_with("DR-AS3-"),
            "a body the lifter cannot follow must be a typed refusal, got {error}"
        ),
    }
}

#[test]
fn retargeting_keeps_the_unmodified_control_flow() {
    let abc: AbcFile = parse_fixture();
    let (body_index, info): (usize, MethodInfo) = target_method(&abc);
    let original: &MethodBody = &abc.method_bodies[body_index];
    let mut shifted_only: MethodBody = insert_junk_after_first_jump(original);
    let lines: Vec<DisasmLine> = disasm(&original.code).expect("disassembles");
    let inserted_at: usize = lines
        .iter()
        .find(|line| line.opcode == OP_JUMP)
        .map(|line| line.offset + 4)
        .expect("jump");
    shifted_only.code[inserted_at] = 0x02;
    let clean: String = rendered(&abc, original, &info).expect("the compiler output lifts");
    let with_nop: String =
        rendered(&abc, &shifted_only, &info).expect("a nop after the jump lifts");
    assert_eq!(
        with_nop, clean,
        "the offset rewrite itself must preserve the method, or the junk-byte case grades nothing"
    );
}
