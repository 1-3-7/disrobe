var out = [];

class Shape {
  #id;
  static count = 0;
  constructor(name) {
    this.name = name;
    this.#id = ++Shape.count;
  }
  get id() {
    return this.#id;
  }
  describe() {
    return this.name + '#' + this.#id;
  }
  static create(name) {
    return new Shape(name);
  }
  hasSameId(other) {
    return #id in other && other.#id === this.#id;
  }
}

class Square extends Shape {
  constructor(side) {
    super('square');
    this.side = side;
  }
  area() {
    return this.side * this.side;
  }
  describe() {
    return super.describe() + ':' + this.area();
  }
}

var square = new Square(3);
var circle = Shape.create('circle');
out.push(square.describe(), circle.describe(), square.id, Shape.count);
out.push(square instanceof Shape, square.hasSameId(square), square.hasSameId(circle));

function kind(value) {
  switch (value) {
    case 'red':
      return 1;
    case 'green':
      return 2;
    case 'blue':
      return 3;
    default:
      return typeof value === 'string' ? 0 : -1;
  }
}
out.push(kind('red'), kind('blue'), kind('pink'), kind(7));

var fns = [];
for (let i = 0; i < 4; i++) {
  let doubled = i * 2;
  fns.push((function (index, twice) {
    return function () {
      return index + twice;
    };
  })(i, doubled));
}
out.push(fns.map(function (f) {
  return f();
}).join('|'));

var pairs = [];
for (const [key, value] of Object.entries({ a: 1, b: 2 })) {
  pairs.push(((k, v) => () => k + v)(key, value));
}
out.push(pairs.map((f) => f()).join(','));

function describeTypes() {
  var values = [undefined, null, 1, 'x', true, {}, [], function () {}, Symbol('s'), 10n];
  return values.map(function (v) {
    if (typeof v === 'function') {
      return 'fn';
    }
    if (typeof v === 'object') {
      return v === null ? 'null' : Array.isArray(v) ? 'array' : 'object';
    }
    return typeof v;
  }).join(',');
}
out.push(describeTypes());

var config = { nested: { value: 5 } };
out.push(config?.nested?.value, config?.missing?.value, config.missing ?? 'fallback');

var { a = 10, b: { c = 20 } = {}, ...rest } = { a: undefined, d: 4, e: 5 };
out.push(a, c, Object.keys(rest).join(''));

var key = 'dyn';
var literal = {
  [key + 'amic']: 1,
  get computed() {
    return 'got';
  },
  method() {
    return 'm';
  },
};
out.push(literal.dynamic, literal.computed, literal.method(), literal.method.name);

function* counter(limit) {
  for (let n = 0; n < limit; n++) {
    yield n;
  }
}
out.push([...counter(4)].join(''));

async function delayed(value) {
  await null;
  return value * 2;
}

delayed(21).then(function (value) {
  out.push(value);
  print(out.join(' '));
});
