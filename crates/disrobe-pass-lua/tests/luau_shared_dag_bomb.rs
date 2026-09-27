#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_lua::reader::common::{LuaChunk, LuaProto};
use disrobe_pass_lua::reader::luau;

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
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

fn write_proto(out: &mut Vec<u8>, child_ids: &[u64]) {
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(0);
    write_varint(out, 0);
    write_varint(out, 0);
    write_varint(out, child_ids.len() as u64);
    for cid in child_ids {
        write_varint(out, *cid);
    }
    write_varint(out, 0);
    write_varint(out, 0);
    out.push(0);
    out.push(0);
}

fn build_shared_dag(depth: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    bytes.push(5);
    bytes.push(0);
    write_varint(&mut bytes, 0);
    write_varint(&mut bytes, (depth + 1) as u64);
    for i in 0..depth {
        let next: u64 = (i + 1) as u64;
        write_proto(&mut bytes, &[next, next]);
    }
    write_proto(&mut bytes, &[]);
    write_varint(&mut bytes, 0);
    bytes
}

const NODE_CEILING: usize = 1 << 16;

fn count_nodes_to_ceiling(proto: &LuaProto) -> usize {
    let mut pending: Vec<&LuaProto> = vec![proto];
    let mut nodes: usize = 0;
    while let Some(next) = pending.pop() {
        nodes += 1;
        if nodes > NODE_CEILING {
            break;
        }
        pending.extend(next.protos.iter());
    }
    nodes
}

#[test]
fn shared_proto_dag_assembles_bounded_no_blowup() {
    let bytes: Vec<u8> = build_shared_dag(60);
    let chunk: LuaChunk = luau::read(&bytes).expect("shared-dag luau chunk parses");
    let nodes: usize = count_nodes_to_ceiling(&chunk.main);
    assert!(
        nodes <= NODE_CEILING,
        "assembled tree must stay within {NODE_CEILING} nodes, got more"
    );
}

#[test]
fn deep_shared_dag_does_not_overflow_or_oom() {
    let bytes: Vec<u8> = build_shared_dag(4096);
    let result: Result<LuaChunk, disrobe_pass_lua::Error> = luau::read(&bytes);
    let chunk: LuaChunk = result.expect("deep shared-dag still returns a chunk");
    let nodes: usize = count_nodes_to_ceiling(&chunk.main);
    assert!(
        nodes <= NODE_CEILING,
        "deep shared-dag must stay within {NODE_CEILING} nodes, got more"
    );
}
