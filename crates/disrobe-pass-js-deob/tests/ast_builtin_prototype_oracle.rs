#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn assert_recovered_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

struct Case {
    label: &'static str,
    input: &'static str,
    expanded_fragment: &'static str,
}

const CASES: &[Case] = &[
    Case {
        label: "array-slice",
        input: "function toArr() { return [].slice.call(arguments).join(','); }\nprint(toArr(1, 2, 3));",
        expanded_fragment: "Array.prototype.slice.call(arguments)",
    },
    Case {
        label: "string-charcodeat",
        input: "print(\"\".charCodeAt.call(\"A\", 0));",
        expanded_fragment: "String.prototype.charCodeAt.call(\"A\", 0)",
    },
    Case {
        label: "number-tostring",
        input: "print((0).toString.call(255, 16));",
        expanded_fragment: "Number.prototype.toString.call(255, 16)",
    },
    Case {
        label: "object-hasownproperty",
        input: "print(({}).hasOwnProperty.call({ a: 1 }, \"a\"));",
        expanded_fragment: "Object.prototype.hasOwnProperty.call({ a: 1 }, \"a\")",
    },
    Case {
        label: "regexp-test",
        input: "print(/ab/.test.call(/b/, \"abc\"));",
        expanded_fragment: "RegExp.prototype.test.call(/b/, \"abc\")",
    },
    Case {
        label: "function-apply",
        input: "function add(a, b) { return a + b; }\nprint((function(){}).apply.call(add, null, [2, 3]));",
        expanded_fragment: "Function.prototype.apply.call(add, null, [2, 3])",
    },
];

#[test]
fn borrowed_prototype_idioms_expand_and_preserve_behavior() {
    for case in CASES {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(case.input);
        assert_eq!(
            stats.builtin_prototypes_expanded, 1,
            "{}: expected exactly one prototype expansion; got {}\n--src--\n{recovered}",
            case.label, stats.builtin_prototypes_expanded
        );
        assert!(
            recovered.contains(case.expanded_fragment),
            "{}: expanded form `{}` missing from recovery\n--src--\n{recovered}",
            case.label,
            case.expanded_fragment
        );
        assert_recovered_equivalent(case.label, case.input, &recovered);
    }
}

#[test]
fn multiple_idioms_in_one_program_all_expand() {
    let input: &str = "print([].slice.call([1, 2, 3]).join('|'));\nprint(\"\".toUpperCase.call(\"ab\"));\nprint((0).toString.call(10, 2));";
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(input);
    assert_eq!(
        stats.builtin_prototypes_expanded, 3,
        "expected three expansions; got {}\n--src--\n{recovered}",
        stats.builtin_prototypes_expanded
    );
    assert!(
        recovered.contains("Array.prototype.slice.call([1, 2, 3])"),
        "{recovered}"
    );
    assert!(
        recovered.contains("String.prototype.toUpperCase.call(\"ab\")"),
        "{recovered}"
    );
    assert!(
        recovered.contains("Number.prototype.toString.call(10, 2)"),
        "{recovered}"
    );
    assert_recovered_equivalent("multi", input, &recovered);
}

#[test]
fn non_borrowed_patterns_are_left_untouched() {
    let cases: &[&str] = &[
        "print([1, 2, 3].slice.call([9, 8, 7]).join(','));",
        "var m = { slice: function () { return 'x'; } };\nprint(m.slice.call(m));",
        "print([].concat([1], [2]).join(','));",
    ];
    for input in cases {
        let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(input);
        assert_eq!(
            stats.builtin_prototypes_expanded, 0,
            "must not fire on non-borrowed pattern\n--in--\n{input}\n--out--\n{recovered}"
        );
        assert!(
            !recovered.contains(".prototype."),
            "no prototype form should be introduced\n--in--\n{input}\n--out--\n{recovered}"
        );
        assert_recovered_equivalent("untouched", input, &recovered);
    }
}
