use core::cell::Cell;

use disrobe_fuzz::python_bytecode::run_fuzz_input;

#[test]
fn the_fuzz_target_exercises_each_mutation_once() {
    let invocation_count: Cell<usize> = Cell::new(0_usize);
    let result: Result<(), &'static str> = run_fuzz_input(b"mutation", |data: &[u8]| {
        invocation_count.set(invocation_count.get() + 1_usize);
        if data == b"mutation" {
            Ok(())
        } else {
            Err("the exercise received different input")
        }
    });
    assert_eq!(result, Ok(()));
    assert_eq!(invocation_count.get(), 1_usize);

    let target_source: &str = include_str!("../fuzz_targets/python_bytecode.rs");
    assert!(target_source.contains("python_bytecode::run_fuzz_input"));
    assert_eq!(
        target_source.matches("python_bytecode::exercise").count(),
        1_usize
    );
    assert!(!target_source.contains("python_bytecode::replay"));
}
