use std::time::Duration;

use disrobe_pass_swift_objc::{render_objc_with_header, render_swift_with_header};

#[test]
fn swift_class_dump_emits_two_line_swift_header() {
    let out: String = render_swift_with_header("class C{}\n", Duration::from_millis(50), "5.10");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Extracted in 50ms with Disrobe"));
    assert_eq!(lines[1], "// Swift 5.10");
}

#[test]
fn objc_class_dump_emits_two_line_objc_header() {
    let out: String =
        render_objc_with_header("@interface X\n@end\n", Duration::from_millis(60), "2.0");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("// Extracted in 60ms with Disrobe"));
    assert_eq!(lines[1], "// Objective-C 2.0");
}
