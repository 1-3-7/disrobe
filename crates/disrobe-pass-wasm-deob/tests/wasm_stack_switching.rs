#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use disrobe_pass_wasm_deob::{Error, StackSwitchOpKind, StackSwitchReport, scan_stack_switching};

const WAT_FULL_STACK_SWITCH: &str = r#"
    (module
      (type $ft (func))
      (type $ct (cont $ft))
      (tag $t)
      (func $worker
        (suspend $t)
        (return))
      (func (export "main")
        (cont.new $ct (ref.func $worker))
        (resume $ct (on $t 0))
        (return)))
"#;

fn baked(src: &str) -> Option<Vec<u8>> {
    wat::parse_str(src).ok()
}

#[test]
fn detects_full_stack_switching_chain_when_supported() {
    let Some(bytes): Option<Vec<u8>> = baked(WAT_FULL_STACK_SWITCH) else {
        return;
    };
    let report: StackSwitchReport = scan_stack_switching(&bytes).expect("scan");
    assert!(!report.is_empty());
    assert!(report.kinds.contains_key(&StackSwitchOpKind::ContNew));
    assert!(report.kinds.contains_key(&StackSwitchOpKind::Suspend));
    assert!(report.kinds.contains_key(&StackSwitchOpKind::Resume));
    let lift: String = report.rust_lift_skeleton();
    assert!(lift.contains("Continuation::new"));
    assert!(lift.contains("suspend_to_tag"));
    assert!(lift.contains("resume_continuation"));
}

#[test]
fn empty_module_reports_no_stack_switching() {
    let bytes: Vec<u8> = wat::parse_str("(module)").expect("wat");
    let report: StackSwitchReport = scan_stack_switching(&bytes).expect("scan");
    assert!(report.is_empty());
}

#[test]
fn rejects_non_wasm_input() {
    let result: Result<StackSwitchReport, Error> = scan_stack_switching(b"\x00\x00\x00\x00");
    assert!(
        matches!(result, Err(Error::Parse(ref msg)) if msg.contains("not a wasm module")),
        "input lacking the wasm magic must be rejected as a parse failure; got {result:?}"
    );
}
