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

fn assert_faithful_input(label: &str, original: &str, input: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let have: String =
        eval_capture(input).unwrap_or_else(|| panic!("{label}: down-compiled input must evaluate"));
    assert_eq!(
        want, have,
        "{label}: hand-written input is not behaviorally identical to the original BEFORE transform"
    );
}

fn run_and_assert_class(label: &str, original: &str, input: &str) -> AstUnminifyStats {
    assert_faithful_input(label, original, input);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(input);
    assert!(
        recovered.contains("class "),
        "{label}: transform must emit a `class` declaration, got:\n{recovered}"
    );
    let want: String = eval_capture(original).expect("orig evaluates");
    let got: String = eval_capture(&recovered)
        .unwrap_or_else(|| panic!("{label}: recovered source must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered class diverged from original\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
    stats
}

const ORIG_BABEL_BASIC: &str = r"
class Point {
  constructor(x, y) { this.x = x; this.y = y; }
  sum() { return this.x + this.y; }
  scale(f) { return this.x * f; }
}
var p = new Point(3, 4);
print(p.sum());
print(p.scale(2));
";

const INPUT_BABEL_BASIC: &str = r#"
function _classCallCheck(instance, Ctor) { if (!(instance instanceof Ctor)) { throw new TypeError("Cannot call a class as a function"); } }
function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var d = props[i]; d.enumerable = d.enumerable || false; d.configurable = true; if ("value" in d) d.writable = true; Object.defineProperty(target, d.key, d); } }
function _createClass(Ctor, protoProps, staticProps) { if (protoProps) _defineProperties(Ctor.prototype, protoProps); if (staticProps) _defineProperties(Ctor, staticProps); return Ctor; }
function Point(x, y) {
  _classCallCheck(this, Point);
  this.x = x;
  this.y = y;
}
_createClass(Point, [{ key: "sum", value: function sum() { return this.x + this.y; } }, { key: "scale", value: function scale(f) { return this.x * f; } }]);
var p = new Point(3, 4);
print(p.sum());
print(p.scale(2));
"#;

#[test]
fn babel_helper_basic_class_reeval_equivalent() {
    let stats: AstUnminifyStats =
        run_and_assert_class("babel/basic", ORIG_BABEL_BASIC, INPUT_BABEL_BASIC);
    assert_eq!(stats.classes_reconstructed, 1);
    assert_eq!(stats.babel_helper_classes, 1);
}

const ORIG_BABEL_STATIC_ACCESSOR: &str = r"
class Counter {
  constructor() { this._n = 10; }
  get value() { return this._n; }
  set value(v) { this._n = v; }
  static make() { return new Counter(); }
}
var c = Counter.make();
print(c.value);
c.value = 42;
print(c.value);
";

const INPUT_BABEL_STATIC_ACCESSOR: &str = r#"
function _classCallCheck(instance, Ctor) { if (!(instance instanceof Ctor)) { throw new TypeError("x"); } }
function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var d = props[i]; d.enumerable = d.enumerable || false; d.configurable = true; if ("value" in d) d.writable = true; Object.defineProperty(target, d.key, d); } }
function _createClass(Ctor, protoProps, staticProps) { if (protoProps) _defineProperties(Ctor.prototype, protoProps); if (staticProps) _defineProperties(Ctor, staticProps); return Ctor; }
function Counter() {
  _classCallCheck(this, Counter);
  this._n = 10;
}
_createClass(Counter, [{ key: "value", get: function get() { return this._n; } }, { key: "value", set: function set(v) { this._n = v; } }], [{ key: "make", value: function make() { return new Counter(); } }]);
var c = Counter.make();
print(c.value);
c.value = 42;
print(c.value);
"#;

#[test]
fn babel_helper_static_and_accessors_reeval_equivalent() {
    let stats: AstUnminifyStats = run_and_assert_class(
        "babel/static-accessor",
        ORIG_BABEL_STATIC_ACCESSOR,
        INPUT_BABEL_STATIC_ACCESSOR,
    );
    assert_eq!(stats.classes_reconstructed, 1);
    assert!(
        stats.static_members_lifted >= 1,
        "static make() must be lifted"
    );
    assert!(stats.accessors_lifted >= 2, "get/set value must be lifted");
}

const ORIG_BABEL_EXTENDS: &str = r"
class Animal {
  constructor(name) { this.name = name; }
  speak() { return this.name + ' makes a sound'; }
}
class Dog extends Animal {
  constructor(name) { super(name); }
  speak() { return this.name + ' barks'; }
}
var d = new Dog('Rex');
print(d.speak());
print(d.name);
";

const INPUT_BABEL_EXTENDS: &str = r#"
function _classCallCheck(instance, Ctor) { if (!(instance instanceof Ctor)) { throw new TypeError("x"); } }
function _defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var d = props[i]; d.enumerable = d.enumerable || false; d.configurable = true; if ("value" in d) d.writable = true; Object.defineProperty(target, d.key, d); } }
function _createClass(Ctor, protoProps, staticProps) { if (protoProps) _defineProperties(Ctor.prototype, protoProps); if (staticProps) _defineProperties(Ctor, staticProps); return Ctor; }
function _getPrototypeOf(o) { return Object.getPrototypeOf(o); }
function _possibleConstructorReturn(self, call) { return call; }
function _inherits(subClass, superClass) { subClass.prototype = Object.create(superClass.prototype, { constructor: { value: subClass, writable: true, configurable: true } }); Object.setPrototypeOf(subClass, superClass); }
function Animal(name) {
  _classCallCheck(this, Animal);
  this.name = name;
}
_createClass(Animal, [{ key: "speak", value: function speak() { return this.name + ' makes a sound'; } }]);
function Dog(name) {
  _classCallCheck(this, Dog);
  return _possibleConstructorReturn(this, _getPrototypeOf(Dog).call(this, name));
}
_inherits(Dog, Animal);
_createClass(Dog, [{ key: "speak", value: function speak() { return this.name + ' barks'; } }]);
var d = new Dog('Rex');
print(d.speak());
print(d.name);
"#;

#[test]
fn babel_helper_extends_super_reeval_equivalent() {
    let stats: AstUnminifyStats =
        run_and_assert_class("babel/extends", ORIG_BABEL_EXTENDS, INPUT_BABEL_EXTENDS);
    assert_eq!(stats.classes_reconstructed, 2);
    assert!(
        stats.classes_with_extends >= 1,
        "Dog extends Animal must be detected"
    );
    let (recovered, _): (String, AstUnminifyStats) = unminify_ast(INPUT_BABEL_EXTENDS);
    assert!(
        recovered.contains("extends Animal"),
        "must render extends clause:\n{recovered}"
    );
    assert!(
        recovered.contains("super(name)"),
        "must rewrite _possibleConstructorReturn into super(name):\n{recovered}"
    );
}

const ORIG_PROTOTYPE: &str = r"
class Rect {
  constructor(w, h) { this.w = w; this.h = h; }
  area() { return this.w * this.h; }
  perimeter() { return 2 * (this.w + this.h); }
}
var r = new Rect(3, 5);
print(r.area());
print(r.perimeter());
";

const INPUT_PROTOTYPE: &str = r"
function Rect(w, h) { this.w = w; this.h = h; }
Rect.prototype.area = function() { return this.w * this.h; };
Rect.prototype.perimeter = function() { return 2 * (this.w + this.h); };
var r = new Rect(3, 5);
print(r.area());
print(r.perimeter());
";

#[test]
fn plain_prototype_class_reeval_equivalent() {
    let stats: AstUnminifyStats =
        run_and_assert_class("prototype/basic", ORIG_PROTOTYPE, INPUT_PROTOTYPE);
    assert_eq!(stats.classes_reconstructed, 1);
    assert_eq!(stats.prototype_classes, 1);
}

const ORIG_PROTOTYPE_INHERIT: &str = r"
class Base {
  constructor(v) { this.v = v; }
  get() { return this.v; }
}
class Derived extends Base {
  twice() { return this.v * 2; }
}
var d = new Derived(7);
print(d.get());
print(d.twice());
";

const INPUT_PROTOTYPE_INHERIT: &str = r"
function Base(v) { this.v = v; }
Base.prototype.get = function() { return this.v; };
function Derived(v) { Base.call(this, v); }
Derived.prototype = Object.create(Base.prototype);
Derived.prototype.twice = function() { return this.v * 2; };
var d = new Derived(7);
print(d.get());
print(d.twice());
";

#[test]
fn plain_prototype_inheritance_reeval_equivalent() {
    let want: String = eval_capture(ORIG_PROTOTYPE_INHERIT).expect("orig evaluates");
    let have: String = eval_capture(INPUT_PROTOTYPE_INHERIT).expect("input evaluates");
    assert_eq!(
        want, have,
        "prototype-inherit input must match original first"
    );
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_PROTOTYPE_INHERIT);
    assert!(stats.classes_reconstructed >= 1, "at least Base recovered");
    assert!(
        recovered.contains("class "),
        "must emit class:\n{recovered}"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "recovered diverged:\n{recovered}");
}

const NEG_PLAIN_FUNCTION: &str = r"
function add(a, b) { return a + b; }
print(add(2, 3));
";

#[test]
fn negative_plain_function_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_PLAIN_FUNCTION);
    assert_eq!(stats.classes_reconstructed, 0, "no class shape present");
    assert!(
        !recovered.contains("class "),
        "must not fabricate a class:\n{recovered}"
    );
}

const NEG_AMBIGUOUS_PROTOTYPE: &str = r"
function Thing(x) { this.x = x; }
var fn = Thing.prototype;
Thing.prototype.go = someExternal;
print('skip');
";

#[test]
fn negative_ambiguous_prototype_left_unchanged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_AMBIGUOUS_PROTOTYPE);
    assert_eq!(
        stats.classes_reconstructed, 0,
        "non-function-expression prototype assignment is ambiguous; must not convert"
    );
    assert!(
        !recovered.contains("class "),
        "must leave ambiguous shape untouched:\n{recovered}"
    );
}

#[test]
fn idempotent_on_already_recovered_class() {
    let (first, _): (String, AstUnminifyStats) = unminify_ast(INPUT_BABEL_BASIC);
    let (second, stats): (String, AstUnminifyStats) = unminify_ast(&first);
    assert_eq!(
        stats.classes_reconstructed, 0,
        "an already-recovered class must not be re-transformed"
    );
    assert_eq!(first, second, "transform must be idempotent");
}
