use std::process::{abort, exit};
use std::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy)]
struct Node {
    header: [u8; 16],
    tag: i32,
    padding_20: i32,
    key: i64,
    tie: i32,
    padding_36: [u8; 12],
    previous: *mut Node,
    next: *mut Node,
    child: *mut Node,
}

const _: () = {
    assert!(std::mem::offset_of!(Node, tag) == 16);
    assert!(std::mem::offset_of!(Node, key) == 24);
    assert!(std::mem::offset_of!(Node, tie) == 32);
    assert!(std::mem::offset_of!(Node, previous) == 48);
    assert!(std::mem::offset_of!(Node, next) == 56);
    assert!(std::mem::offset_of!(Node, child) == 64);
    assert!(std::mem::size_of::<Node>() == 72);
};

const EMPTY: Node = Node {
    header: [0; 16],
    tag: 0,
    padding_20: 0,
    key: 0,
    tie: 0,
    padding_36: [0; 12],
    previous: null_mut(),
    next: null_mut(),
    child: null_mut(),
};

const NODES: usize = 10;

#[no_mangle]
pub extern "C" fn sub_1400058c0(_: u64, _: u64, _: u64, _: u64) -> u64 {
    abort()
}

#[no_mangle]
pub extern "C" fn sub_140005920(_: u64, _: u64, _: u64, _: u64) -> u64 {
    abort()
}

unsafe fn merge(left: *mut Node, right: *mut Node) -> *mut Node {
    let left_first: bool = (*left).key < (*right).key
        || ((*left).key == (*right).key && (*left).tie < (*right).tie);
    let (winner, loser): (*mut Node, *mut Node) = if left_first {
        (left, right)
    } else {
        (right, left)
    };
    (*loser).next = (*winner).child;
    if !(*winner).child.is_null() {
        (*(*winner).child).previous = loser;
    }
    (*loser).previous = winner;
    (*winner).child = loser;
    winner
}

unsafe fn combine(mut list: *mut Node) -> *mut Node {
    let mut pending: *mut Node = null_mut();
    while !list.is_null() {
        let left: *mut Node = list;
        let right: *mut Node = (*left).next;
        list = if right.is_null() {
            null_mut()
        } else {
            (*right).next
        };
        let pair: *mut Node = if right.is_null() {
            left
        } else {
            merge(left, right)
        };
        (*pair).previous = pending;
        pending = pair;
    }
    let mut result: *mut Node = null_mut();
    while !pending.is_null() {
        let prior: *mut Node = (*pending).previous;
        result = if result.is_null() {
            pending
        } else {
            merge(result, pending)
        };
        pending = prior;
    }
    if !result.is_null() {
        (*result).next = null_mut();
    }
    result
}

unsafe fn initialise(nodes: *mut Node, count: usize, order: &[u32; 5], mode: u32, children: u32) {
    const SIGNED_KEYS: [i64; 5] = [i64::MIN, -1, 0, 1, i64::MAX];
    for i in 0..count {
        let node: *mut Node = nodes.add(i);
        (*node).tag = 1;
        (*node).key = match mode {
            0 => i64::from(order[i]),
            1 => SIGNED_KEYS[order[i] as usize],
            _ => 7,
        };
        (*node).tie = if mode == 2 { order[i] as i32 - 2 } else { 0 };
        (*node).previous = if i == 0 { null_mut() } else { nodes.add(i - 1) };
        (*node).next = if i + 1 == count {
            null_mut()
        } else {
            nodes.add(i + 1)
        };
        if children != 0 {
            let child: *mut Node = nodes.add(5 + i);
            (*node).child = child;
            (*child).tag = 1;
            (*child).previous = node;
        }
    }
}

fn node_index(nodes: *const Node, node: *const Node) -> i64 {
    if node.is_null() {
        return -1;
    }
    let base: usize = nodes as usize;
    let address: usize = node as usize;
    let width: usize = std::mem::size_of::<Node>();
    if address < base || address >= base + NODES * width || (address - base) % width != 0 {
        return -2;
    }
    ((address - base) / width) as i64
}

unsafe fn grade(cases: &mut u32, count: usize, order: &[u32; 5], mode: u32, children: u32) {
    let mut expected: [Node; NODES] = [EMPTY; NODES];
    let mut observed: [Node; NODES] = [EMPTY; NODES];
    let want_base: *mut Node = expected.as_mut_ptr();
    let got_base: *mut Node = observed.as_mut_ptr();
    initialise(want_base, count, order, mode, children);
    initialise(got_base, count, order, mode, children);
    let want: *mut Node = combine(if count == 0 { null_mut() } else { want_base });
    let got: *mut Node = body::sub_140014e50(
        if count == 0 { 0 } else { got_base as usize as u64 },
        0,
        0,
        0,
    ) as usize as *mut Node;
    if node_index(want_base, want) != node_index(got_base, got) {
        eprintln!("root mismatch in case {cases}");
        exit(1);
    }
    for i in 0..NODES {
        let left: *const Node = want_base.add(i);
        let right: *const Node = got_base.add(i);
        if (*left).header != (*right).header
            || (*left).padding_20 != (*right).padding_20
            || (*left).padding_36 != (*right).padding_36
            || (*left).tag != (*right).tag
            || (*left).key != (*right).key
            || (*left).tie != (*right).tie
            || node_index(want_base, (*left).previous) != node_index(got_base, (*right).previous)
            || node_index(want_base, (*left).next) != node_index(got_base, (*right).next)
            || node_index(want_base, (*left).child) != node_index(got_base, (*right).child)
        {
            eprintln!("node {i} mismatch in case {cases}");
            exit(1);
        }
    }
    *cases += 1;
}

unsafe fn permutations(cases: &mut u32, count: usize, depth: usize, order: &mut [u32; 5], used: u32) {
    if depth == count {
        for mode in 0..3 {
            for children in 0..2 {
                grade(cases, count, order, mode, children);
            }
        }
        return;
    }
    for value in 0..count as u32 {
        if used & (1 << value) == 0 {
            order[depth] = value;
            permutations(cases, count, depth + 1, order, used | (1 << value));
        }
    }
}

fn main() {
    let mut order: [u32; 5] = [0, 1, 2, 3, 4];
    let mut cases: u32 = 0;
    unsafe {
        grade(&mut cases, 0, &order, 0, 0);
        for count in 1..=5 {
            permutations(&mut cases, count, 0, &mut order, 0);
            grade(&mut cases, count, &order, 3, 0);
            grade(&mut cases, count, &order, 3, 1);
        }
    }
    println!("{cases}");
}
