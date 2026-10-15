use crate::disasm::JumpDests;
use crate::exec::{Halt, Machine, NullSink, State, Stop, split_branch};
use crate::expr::Val;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Split {
    pub(crate) runtime_offset: usize,
    pub(crate) runtime_len: usize,
}

pub(crate) fn split(code: &[u8], dests: &JumpDests, budget: &mut u64) -> Option<Split> {
    let machine: Machine<'_> = Machine {
        code,
        dests,
        codesize_known: false,
        fork_selector_buckets: false,
    };
    let mut sink: NullSink = NullSink;
    let mut work: Vec<State> = vec![State::default()];
    let mut paths: usize = 0;
    while let Some(mut state) = work.pop() {
        paths += 1;
        if paths > 4096 || *budget == 0 {
            return None;
        }
        match machine.run(&mut state, &mut sink, budget, false) {
            Stop::JumpDest => work.push(state),
            Stop::Halt(Halt::Return(data)) => {
                let Some(size) = data.size else {
                    continue;
                };
                let found: Option<&(Val, u64, u64)> = state
                    .code_copies
                    .iter()
                    .rev()
                    .find(|(to, _, count): &&(Val, u64, u64)| *to == data.origin && *count == size);
                if let Some((_, start, count)) = found {
                    let start: usize = usize::try_from(*start).ok()?;
                    let len: usize = usize::try_from(*count).ok()?;
                    if len > 0
                        && start
                            .checked_add(len)
                            .is_some_and(|end: usize| end <= code.len())
                    {
                        return Some(Split {
                            runtime_offset: start,
                            runtime_len: len,
                        });
                    }
                }
            }
            Stop::Halt(_) | Stop::Bucket(_) => {}
            Stop::Branch {
                target,
                fallthrough,
                ..
            } => {
                let Some(target) = target else {
                    work.push(state);
                    continue;
                };
                if !state.note_fork(fallthrough - 1, dests) {
                    continue;
                }
                let (taken, fall) = split_branch(&state, target, fallthrough);
                work.push(taken);
                work.push(fall);
            }
        }
    }
    None
}
