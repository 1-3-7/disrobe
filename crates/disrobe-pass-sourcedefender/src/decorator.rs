#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecoratorStripReport {
    pub stripped_count: usize,
    pub matched_lines: Vec<usize>,
    pub source: String,
}

const DECORATOR_PREFIXES: &[&str] = &[
    "@sourcedefender.decorator",
    "@sourcedefender.protect",
    "@sourcedefender.module",
    "@sourcedefender(",
    "@sd_decrypt",
    "@sourcedefender_decrypt",
];

#[inline]
#[must_use]
pub fn strip_sourcedefender_decorators(source: &str) -> DecoratorStripReport {
    let mut out: String = String::with_capacity(source.len());
    let mut stripped_count: usize = 0usize;
    let mut matched_lines: Vec<usize> = Vec::new();
    for (idx, line) in source.split_inclusive('\n').enumerate() {
        let trimmed: &str = line.trim_start();
        if is_decorator_line(trimmed) {
            stripped_count += 1;
            matched_lines.push(idx);
            continue;
        }
        out.push_str(line);
    }
    DecoratorStripReport {
        stripped_count,
        matched_lines,
        source: out,
    }
}

#[inline]
fn is_decorator_line(trimmed: &str) -> bool {
    DECORATOR_PREFIXES.iter().any(|p| trimmed.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_decorator_means_no_strip() {
        let src: &str = "def foo():\n    return 1\n";
        let r: DecoratorStripReport = strip_sourcedefender_decorators(src);
        assert_eq!(r.stripped_count, 0);
        assert_eq!(r.source, src);
    }

    #[test]
    fn strips_single_decorator() {
        let src: &str = "@sourcedefender.decorator\ndef foo():\n    return 1\n";
        let r: DecoratorStripReport = strip_sourcedefender_decorators(src);
        assert_eq!(r.stripped_count, 1);
        assert_eq!(r.source, "def foo():\n    return 1\n");
        assert_eq!(r.matched_lines, vec![0]);
    }

    #[test]
    fn strips_multiple_decorators_independently() {
        let src: &str = concat!(
            "@sourcedefender.decorator\n",
            "def a():\n",
            "    return 1\n",
            "@sourcedefender.protect\n",
            "def b():\n",
            "    return 2\n",
        );
        let r: DecoratorStripReport = strip_sourcedefender_decorators(src);
        assert_eq!(r.stripped_count, 2);
        assert!(!r.source.contains("@sourcedefender"));
        assert_eq!(r.matched_lines, vec![0, 3]);
    }

    #[test]
    fn leaves_other_decorators_intact() {
        let src: &str = "@staticmethod\n@sourcedefender.decorator\ndef foo():\n    pass\n";
        let r: DecoratorStripReport = strip_sourcedefender_decorators(src);
        assert_eq!(r.stripped_count, 1);
        assert!(r.source.contains("@staticmethod"));
        assert!(!r.source.contains("@sourcedefender"));
    }
}
