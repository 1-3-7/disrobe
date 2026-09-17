use std::time::Duration;

use disrobe_pass_sourcedefender::render_decoded_with_header;

#[test]
fn sourcedefender_decoded_emits_two_line_python_header() {
    let out: String = render_decoded_with_header("x = 1\n", Duration::from_millis(220), "3.12");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Decoded in 220ms with Disrobe"));
    assert_eq!(lines[1], "# Python 3.12");
}
