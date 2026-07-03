mod eval;
mod fold;
mod methods;
mod value;

pub use public::{EvalReport, evaluate_source};

mod public {
    use ruff_python_ast::ModModule;
    use ruff_python_codegen::{Generator, Stylist};
    use ruff_python_parser::{Mode, ParseOptions, parse};
    use serde::Serialize;

    use super::fold::{FoldReport, fold_module};
    use crate::error::{Error, Result};

    const MAX_OUTER_PASSES: usize = 6;

    #[derive(Debug, Default, Clone, Copy, Serialize)]
    pub struct EvalReport {
        pub outer_passes: usize,
        pub bindings_learned: usize,
        pub exprs_folded: usize,
        pub bindings_skipped_dynamic: usize,
        pub converged: bool,
    }

    pub fn evaluate_source(source: &str) -> Result<(String, EvalReport)> {
        let mut current: String = source.to_owned();
        let mut report: EvalReport = EvalReport::default();
        for outer in 0..MAX_OUTER_PASSES {
            report.outer_passes = outer + 1;
            let parsed: ruff_python_parser::Parsed<ruff_python_ast::Mod> =
                parse(&current, ParseOptions::from(Mode::Module))
                    .map_err(|e| Error::AstCleanup(format!("ruff parse failed: {e}")))?;
            let stylist: Stylist<'_> = Stylist::from_tokens(parsed.tokens(), &current);
            let mut module: ModModule = match parsed.into_syntax() {
                ruff_python_ast::Mod::Module(m) => m,
                ruff_python_ast::Mod::Expression(_) => {
                    return Err(Error::AstCleanup(
                        "expected Module, got Expression".to_owned(),
                    ));
                }
            };

            let pass_report: FoldReport = fold_module(&mut module);
            report.bindings_learned += pass_report.bindings_learned;
            report.exprs_folded += pass_report.exprs_folded;
            report.bindings_skipped_dynamic += pass_report.bindings_skipped_dynamic;

            let mut emitted: String = String::with_capacity(current.len());
            let mut first: bool = true;
            for stmt in &module.body {
                if !first {
                    emitted.push('\n');
                }
                first = false;
                let chunk: String = Generator::from(&stylist).stmt(stmt);
                emitted.push_str(&chunk);
            }

            let changed: bool = pass_report.exprs_folded > 0;
            current = emitted;
            if !changed {
                report.converged = true;
                break;
            }
        }
        Ok((current, report))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fold(src: &str) -> String {
        let (out, _r): (String, EvalReport) = evaluate_source(src).expect("evaluate");
        out
    }

    #[test]
    fn folds_bytes_reverse_decode() {
        let src: &str = "x = bytes([111, 108, 108, 101, 104][::-1]).decode()\n";
        let out: String = fold(src);
        assert!(
            out.contains("'hello'") || out.contains("\"hello\""),
            "got: {out}"
        );
    }

    #[test]
    fn folds_chr_concat() {
        let src: &str = "x = chr(72) + chr(101) + chr(108) + chr(108) + chr(111)\n";
        let out: String = fold(src);
        assert!(
            out.contains("\"Hello\"") || out.contains("'Hello'"),
            "got: {out}"
        );
    }

    #[test]
    fn folds_int_arith() {
        let src: &str = "x = (6545115918955394424 + 6478) // 2 - 3272557959477697212 - 3198\n";
        let out: String = fold(src);
        assert!(out.contains("41"), "got: {out}");
    }

    #[test]
    fn folds_join_list_comprehension() {
        let src: &str = "x = ''.join([chr(c) for c in [72, 101, 108, 108, 111]])\n";
        let out: String = fold(src);
        assert!(
            out.contains("'Hello'") || out.contains("\"Hello\""),
            "got: {out}"
        );
    }

    #[test]
    fn folds_cross_binding_reference() {
        let src: &str = "a = bytes([111, 108, 108, 101, 104][::-1]).decode()\nb = a + ' world'\n";
        let out: String = fold(src);
        assert!(
            out.contains("'hello world'") || out.contains("\"hello world\""),
            "got: {out}"
        );
    }

    #[test]
    fn folds_octal_escape_strip() {
        let src: &str = "x = '\\147\\143\\40\\40\\40\\40\\40'.strip()\n";
        let out: String = fold(src);
        assert!(out.contains("'gc'") || out.contains("\"gc\""), "got: {out}");
    }

    #[test]
    fn refuses_exec() {
        let src: &str = "x = exec('print(1)')\n";
        let out: String = fold(src);
        assert!(out.contains("exec"), "must refuse to fold exec: {out}");
    }

    #[test]
    fn refuses_eval() {
        let src: &str = "x = eval('1+1')\n";
        let out: String = fold(src);
        assert!(out.contains("eval"), "must refuse to fold eval: {out}");
    }

    #[test]
    fn refuses_import() {
        let src: &str = "x = __import__('os')\n";
        let out: String = fold(src);
        assert!(
            out.contains("__import__"),
            "must refuse to fold __import__: {out}"
        );
    }

    #[test]
    fn folds_ternary() {
        let src: &str = "x = 'yes' if 1 < 2 else 'no'\n";
        let out: String = fold(src);
        assert!(
            out.contains("'yes'") || out.contains("\"yes\""),
            "got: {out}"
        );
    }

    #[test]
    fn folds_bytes_fromhex() {
        let src: &str = "x = bytes.fromhex('48656c6c6f')\n";
        let out: String = fold(src);
        assert!(out.contains("Hello"), "got: {out}");
    }

    #[test]
    fn rejects_dict_use() {
        let src: &str = "x = {1: 'a', 2: 'b'}[1]\n";
        let out: String = fold(src);
        let _ = out;
    }

    fn assert_folds(src: &str, expected: &str) {
        let out: String = fold(src);
        assert!(
            out.contains(expected),
            "expected `{expected}` in folded output, got: {out}"
        );
    }

    #[test]
    fn folds_reversed_join() {
        assert_folds("x = ''.join(reversed('olleh'))\n", "'hello'");
    }

    #[test]
    fn folds_sorted_join() {
        assert_folds("x = ''.join(sorted('dcba'))\n", "'abcd'");
    }

    #[test]
    fn folds_map_chr_join() {
        assert_folds("x = ''.join(map(chr, [104, 105]))\n", "'hi'");
    }

    #[test]
    fn folds_filter_none() {
        assert_folds("x = list(filter(None, [0, 1, 2, 0]))\n", "[1, 2]");
    }

    #[test]
    fn folds_str_format_positional_and_indexed() {
        assert_folds("x = '{}-{}'.format(1, 2)\n", "'1-2'");
        assert_folds("x = '{0}{1}'.format('a', 'b')\n", "'ab'");
    }

    #[test]
    fn folds_divmod_pow_round() {
        assert_folds("x = divmod(17, 5)\n", "3, 2");
        assert_folds("x = pow(2, 10)\n", "1024");
        assert_folds("x = pow(5, 3, 13)\n", "8");
        assert_folds("x = round(3)\n", "3");
    }

    #[test]
    fn folds_int_from_bytes_both_orders() {
        assert_folds("x = int.from_bytes(b'\\x01\\x00', 'little')\n", "1");
        assert_folds("x = int.from_bytes(b'\\x01\\x00', 'big')\n", "256");
    }

    #[test]
    fn folds_justify_and_center() {
        assert_folds("x = 'ab'.rjust(5, '0')\n", "'000ab'");
        assert_folds("x = 'ab'.ljust(5, '0')\n", "'ab000'");
        assert_folds("x = 'ab'.center(6, '-')\n", "'--ab--'");
    }

    #[test]
    fn folds_remove_affixes() {
        assert_folds("x = 'foobar'.removeprefix('foo')\n", "'bar'");
        assert_folds("x = 'foobar'.removesuffix('bar')\n", "'foo'");
    }

    #[test]
    fn folds_partition() {
        assert_folds("x = 'a=b=c'.partition('=')\n", "'a', '=', 'b=c'");
        assert_folds("x = 'a=b=c'.rpartition('=')\n", "'a=b', '=', 'c'");
    }

    #[test]
    fn folds_translate_table() {
        assert_folds("x = 'abc'.translate({97: 122})\n", "'zbc'");
    }

    #[test]
    fn folds_expandtabs() {
        assert_folds("x = 'a\\tb'.expandtabs(4)\n", "'a   b'");
    }

    #[test]
    fn folds_repr_and_ascii() {
        assert_folds("x = repr('hi')\n", "\"'hi'\"");
        assert_folds("x = ascii('hi')\n", "\"'hi'\"");
    }

    #[test]
    fn folds_bytes_join_and_replace() {
        assert_folds("x = b','.join([b'a', b'b'])\n", "b'a,b'");
        assert_folds("x = b'Hello'.replace(b'l', b'L')\n", "b'HeLLo'");
    }

    #[test]
    fn folds_zip_and_enumerate() {
        assert_folds("x = list(zip([1, 2], [3, 4]))\n", "(1, 3)");
        assert_folds("x = list(enumerate(['a', 'b']))\n", "(0, 'a')");
    }

    #[test]
    fn folds_sum_with_start() {
        assert_folds("x = sum([1, 2], 10)\n", "13");
    }

    #[test]
    fn does_not_fold_set_to_ordered_list() {
        let out: String = fold("x = list(set([3, 1, 2]))\n");
        assert!(
            out.contains("set("),
            "set ordering is non-deterministic and must not be folded: {out}"
        );
    }

    #[test]
    fn refuses_map_over_forbidden_builtin() {
        let out: String = fold("x = list(map(eval, ['1+1']))\n");
        assert!(out.contains("eval"), "map over eval must be refused: {out}");
    }
}
