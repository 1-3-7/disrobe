#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

fn restore(input: &str) -> (String, AstUnminifyStats) {
    unminify_ast(input)
}

const HOST_SIMPLE: &str = "var a = React.createElement(\"div\", null, \"hello\");\n";

#[test]
fn host_element_with_text_child() {
    let (out, stats): (String, AstUnminifyStats) = restore(HOST_SIMPLE);
    assert!(
        stats.jsx_elements_restored >= 1,
        "createElement must restore; got {}",
        stats.jsx_elements_restored
    );
    assert!(
        out.contains("<div>hello</div>"),
        "expected `<div>hello</div>`:\n{out}"
    );
    assert!(
        !out.contains("createElement"),
        "the createElement call must be gone:\n{out}"
    );
}

const HOST_PROPS: &str =
    "var a = React.createElement(\"a\", { href: \"/x\", id: \"link\" }, \"go\");\n";

#[test]
fn host_element_string_props_become_attributes() {
    let (out, stats): (String, AstUnminifyStats) = restore(HOST_PROPS);
    assert!(stats.jsx_elements_restored >= 1, "must restore");
    assert!(
        out.contains("<a href=\"/x\" id=\"link\">go</a>"),
        "expected attributes:\n{out}"
    );
}

const BOOL_AND_EXPR_PROPS: &str =
    "var a = React.createElement(\"input\", { disabled: true, value: count });\n";

#[test]
fn boolean_and_expression_props() {
    let (out, stats): (String, AstUnminifyStats) = restore(BOOL_AND_EXPR_PROPS);
    assert!(stats.jsx_elements_restored >= 1, "must restore");
    assert!(
        out.contains("<input disabled value={count} />"),
        "expected boolean and expression attrs:\n{out}"
    );
}

const SPREAD_PROPS: &str = "var a = React.createElement(\"div\", { ...rest, id: \"x\" });\n";

#[test]
fn spread_props_are_preserved() {
    let (out, stats): (String, AstUnminifyStats) = restore(SPREAD_PROPS);
    assert!(stats.jsx_elements_restored >= 1, "must restore");
    assert!(
        out.contains("<div {...rest} id=\"x\" />"),
        "expected spread attr:\n{out}"
    );
}

const COMPONENT_TAG: &str =
    "var a = React.createElement(Button, { kind: \"primary\" }, \"Save\");\n";

#[test]
fn component_identifier_tag() {
    let (out, stats): (String, AstUnminifyStats) = restore(COMPONENT_TAG);
    assert!(stats.jsx_elements_restored >= 1, "must restore");
    assert!(
        out.contains("<Button kind=\"primary\">Save</Button>"),
        "expected component element:\n{out}"
    );
}

const NESTED: &str = "var a = React.createElement(\"ul\", null, React.createElement(\"li\", null, \"one\"), React.createElement(\"li\", null, \"two\"));\n";

#[test]
fn nested_create_element_becomes_nested_jsx() {
    let (out, stats): (String, AstUnminifyStats) = restore(NESTED);
    assert!(
        stats.jsx_elements_restored >= 3,
        "ul + 2 li must all restore; got {}",
        stats.jsx_elements_restored
    );
    assert!(
        out.contains("<ul><li>one</li><li>two</li></ul>"),
        "expected nested jsx:\n{out}"
    );
}

const EXPR_CHILD: &str = "var a = React.createElement(\"span\", null, name);\n";

#[test]
fn expression_child_is_wrapped_in_braces() {
    let (out, stats): (String, AstUnminifyStats) = restore(EXPR_CHILD);
    assert!(stats.jsx_elements_restored >= 1, "must restore");
    assert!(
        out.contains("<span>{name}</span>"),
        "expected expression child:\n{out}"
    );
}

const FRAGMENT: &str =
    "var a = React.createElement(React.Fragment, null, React.createElement(\"p\", null, \"x\"));\n";

#[test]
fn react_fragment_becomes_empty_tags() {
    let (out, stats): (String, AstUnminifyStats) = restore(FRAGMENT);
    assert!(
        stats.jsx_fragments_restored >= 1,
        "React.Fragment must restore as <>; got {}",
        stats.jsx_fragments_restored
    );
    assert!(out.contains("<><p>x</p></>"), "expected fragment:\n{out}");
}

const SELF_CLOSING: &str = "var a = React.createElement(\"br\", null);\n";

#[test]
fn childless_element_self_closes() {
    let (out, stats): (String, AstUnminifyStats) = restore(SELF_CLOSING);
    assert!(stats.jsx_elements_restored >= 1, "must restore");
    assert!(out.contains("<br />"), "expected self-closing:\n{out}");
}

const NEG_NOT_CREATE_ELEMENT: &str = "var a = React.cloneElement(x, null, \"y\");\n";

#[test]
fn unrelated_react_call_is_untouched() {
    let (out, stats): (String, AstUnminifyStats) = restore(NEG_NOT_CREATE_ELEMENT);
    assert_eq!(
        stats.jsx_elements_restored, 0,
        "cloneElement is not createElement and must NOT be rewritten"
    );
    assert!(
        out.contains("React.cloneElement"),
        "the call must be preserved:\n{out}"
    );
}

const NEG_DYNAMIC_PROPS: &str = "var a = React.createElement(\"div\", props, \"x\");\n";

#[test]
fn non_object_props_identifier_is_skipped() {
    let (out, stats): (String, AstUnminifyStats) = restore(NEG_DYNAMIC_PROPS);
    assert_eq!(
        stats.jsx_elements_restored, 0,
        "a non-null identifier props bag is ambiguous and must be skipped"
    );
    assert!(
        out.contains("createElement"),
        "the call must be preserved when props cannot be rendered:\n{out}"
    );
}

const NEG_COMPUTED_KEY: &str = "var a = React.createElement(\"div\", { [dyn]: 1 }, \"x\");\n";

#[test]
fn computed_prop_key_is_skipped() {
    let (_out, stats): (String, AstUnminifyStats) = restore(NEG_COMPUTED_KEY);
    assert_eq!(
        stats.jsx_elements_restored, 0,
        "a computed prop key cannot be a static JSX attribute and must be skipped"
    );
}
