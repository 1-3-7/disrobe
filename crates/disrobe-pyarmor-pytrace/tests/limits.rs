use disrobe_pytrace::test_support;

#[test]
fn skip_recognizes_stdlib_unix_path() {
    let lower: &str = "/usr/lib/python3.11/runpy.py";
    assert!(test_support::should_skip_path(lower));
}

#[test]
fn skip_recognizes_stdlib_windows_path() {
    let lower: &str = "c:\\python311\\lib\\runpy.py";
    assert!(test_support::should_skip_path(lower));
}

#[test]
fn skip_recognizes_site_packages() {
    let lower: &str = "/home/user/.venv/lib/python3.11/site-packages/foo.py";
    assert!(test_support::should_skip_path(lower));
}

#[test]
fn skip_recognizes_helper_script() {
    let lower: &str = "/tmp/v6v7_dynamic_hook.py";
    assert!(test_support::should_skip_path(lower));
}

#[test]
fn skip_recognizes_self_module() {
    let lower: &str = "<disrobe_pytrace internal>";
    assert!(test_support::should_skip_path(lower));
}

#[test]
fn skip_passes_user_wrapper() {
    let lower: &str = "c:\\users\\someone\\desktop\\hello.py";
    assert!(!test_support::should_skip_path(lower));
}

#[test]
fn skip_passes_arbitrary_user_file() {
    let lower: &str = "/home/user/projects/myapp/main.py";
    assert!(!test_support::should_skip_path(lower));
}

#[test]
fn filter_needles_are_non_empty() {
    assert!(test_support::filter_needles_are_non_empty());
}

#[test]
fn limitation_message_mentions_c_eval_gap() {
    let msg: &str = test_support::limitation_message();
    assert!(msg.contains("PyEval_EvalCode"));
    assert!(msg.contains("sys.settrace"));
    assert!(msg.contains("disrobe-pyarmor-cextract"));
}

#[test]
fn drain_reserve_is_capped() {
    assert_eq!(
        test_support::drain_reserve(test_support::max_drain_outputs() + 1),
        test_support::max_drain_outputs()
    );
    assert_eq!(test_support::drain_reserve(7), 7);
}

#[test]
fn drain_total_rejects_oversized_code_object() {
    assert!(test_support::drain_total_is_err(
        0,
        test_support::max_marshaled_code_bytes() + 1
    ));
}
