use std::time::Duration;

use disrobe_pass_pyfreeze::render_extracted_with_header;

#[test]
fn pyfreeze_extracted_emits_two_line_python_header() {
    let out: String = render_extracted_with_header("payload\n", Duration::from_millis(120), "3.12");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Extracted in 120ms with Disrobe"));
    assert_eq!(lines[1], "# Python 3.12");
}
