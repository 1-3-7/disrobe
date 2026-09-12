use std::time::Duration;

use disrobe_pass_php::{render_php_deobfuscated_with_header, render_php_extracted_with_header};

#[test]
fn php_deob_emits_two_line_php_header() {
    let out: String =
        render_php_deobfuscated_with_header("<?php echo 1; ?>\n", Duration::from_millis(8), "8.3");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Deobfuscated in 8ms with Disrobe"));
    assert_eq!(lines[1], "# PHP 8.3");
}

#[test]
fn php_extracted_emits_two_line_php_header() {
    let out: String =
        render_php_extracted_with_header("<?php // phar ?>\n", Duration::from_millis(12), "8.2");
    let lines: Vec<&str> = out.lines().collect();
    assert!(lines[0].starts_with("# Extracted in 12ms with Disrobe"));
    assert_eq!(lines[1], "# PHP 8.2");
}
