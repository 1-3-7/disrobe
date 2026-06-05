use std::time::Duration;

use disrobe_pass_pyinstaller::render_extracted_with_header;

#[test]
fn pyinstaller_extracted_emits_two_line_python_header() {
    let body: &str = "module\n";
    let out: String = render_extracted_with_header(body, Duration::from_millis(40), "3.13");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Extracted in 40ms with Disrobe"));
    assert_eq!(lines[1], "# Python 3.13");
}
