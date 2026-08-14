function bigText() {
  return String(123456789012345678901234567890n + 1n);
}

function tag(name) {
  return `hi-${name}-${name.length}`;
}

function surrogate() {
  return "a\u{1F600}b".length + ":" + "\u{1F600}".charCodeAt(0);
}

var triple = function (x) {
  return x * 3;
};

var arrow = (x) => x + 1;

function makeBox(v) {
  return {
    v: v,
    get twice() {
      return this.v * 2;
    },
    set twice(x) {
      this.v = x - 1;
    },
    plus: function (o) {
      return this.v + o.v;
    }
  };
}

function* seq(n) {
  for (var i = 0; i < n; i = i + 1) {
    yield i;
  }
}

function drain(n) {
  var s = 0;
  for (var x of seq(n)) {
    s = s + x;
  }
  return s;
}

function widest(a) {
  return Math.max.apply(null, a);
}

function shape() {
  var o = { a: 1, b: 2, c: 3 };
  var out = "";
  var names = Object.keys(o);
  for (var i = 0; i < names.length; i = i + 1) {
    out = out + names[i] + o[names[i]];
  }
  return out;
}

print(bigText());
print(tag("box"));
print(surrogate());
print(triple(7));
print(arrow(41));
var b = makeBox(10);
print(b.twice);
b.twice = 9;
print(b.v);
print(b.plus(makeBox(5)));
print(drain(5));
print(widest([3, 11, 7]));
print(shape());
