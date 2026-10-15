function* range(start, end, step) {
  for (var i = start; i < end; i += step) yield i;
  return 'done';
}

function* echo() {
  var received = [];
  var value = yield 'ready';
  while (value !== 'stop') {
    received.push(value);
    value = yield received.length;
  }
  return received.join('+');
}

function* fib() {
  var a = 0, b = 1;
  for (;;) {
    yield a;
    var t = a + b;
    a = b;
    b = t;
  }
}

function take(gen, n) {
  var out = [];
  for (var v of gen) {
    if (out.length >= n) break;
    out.push(v);
  }
  return out;
}

var r = range(0, 10, 3);
print(r.next().value, r.next().value, r.next().value, r.next().value, JSON.stringify(r.next()));
var e = echo();
print(e.next().value, e.next('x').value, e.next('y').value, JSON.stringify(e.next('stop')));
print(take(fib(), 10).join(','));
print([...range(1, 6, 1)].join(''));
var g = range(0, 3, 1);
print(g.next().value, JSON.stringify(g.return(42)), JSON.stringify(g.next()));
function* thrower() {
  try {
    yield 1;
  } catch (err) {
    yield 'caught ' + err;
  }
}
var t = thrower();
print(t.next().value, t.throw('oops').value, t.next().done);
