var log = [];

function* inner(tag) {
  try {
    var first = yield tag + ':1';
    log.push(tag + ' got ' + first);
    var second = yield tag + ':2';
    log.push(tag + ' got ' + second);
    return tag + ':done';
  } catch (e) {
    log.push(tag + ' caught ' + e);
    yield tag + ':recovered';
    return tag + ':after-catch';
  } finally {
    log.push(tag + ' finally');
  }
}

function* outer() {
  var a = yield* inner('a');
  log.push('outer a=' + a);
  var b = yield* [10, 20];
  log.push('outer b=' + b);
  var c = yield* inner('c');
  return 'outer:' + c;
}

var g = outer();
print(JSON.stringify(g.next('ignored')));
print(JSON.stringify(g.next('x')));
print(JSON.stringify(g.next('y')));
print(JSON.stringify(g.next()));
print(JSON.stringify(g.next()));
print(JSON.stringify(g.throw('boom')));
print(JSON.stringify(g.next()));
print(log.join('|'));

log = [];
var h = outer();
h.next();
print(JSON.stringify(h.return('stop')), JSON.stringify(h.next()), log.join('|'));

var noThrow = {};
noThrow[Symbol.iterator] = function () {
  return {
    next: function () {
      return { value: 'nt', done: false };
    },
    return: function () {
      log.push('nt closed');
      return {};
    }
  };
};

function* usesNoThrow() {
  yield* noThrow;
}

log = [];
var u = usesNoThrow();
u.next();
try {
  u.throw(new Error('x'));
} catch (e) {
  print('nothrow', e instanceof TypeError, log.join('|'));
}

var marker = { value: 'm', done: false, extra: 42 };
var custom = {};
custom[Symbol.iterator] = function () {
  var n = 0;
  return {
    next: function (sent) {
      n++;
      log.push('custom next ' + sent);
      return n === 1 ? marker : { value: 'end:' + sent, done: true };
    }
  };
};

function* passThrough() {
  return yield* custom;
}

log = [];
var pt = passThrough();
var firstResult = pt.next('a');
print(firstResult === marker, firstResult.extra, JSON.stringify(pt.next('b')), log.join('|'));

function* lazyReturn() {
  var reply = yield* {
    [Symbol.iterator]: function () {
      var step = 0;
      return {
        next: function () {
          step++;
          return { value: 'lazy' + step, done: false };
        },
        return: function (value) {
          log.push('lazy return ' + value);
          return step < 2 ? { value: 'not yet', done: false } : { value: value, done: true };
        }
      };
    }
  };
  log.push('never ' + reply);
}

log = [];
var lr = lazyReturn();
print(JSON.stringify(lr.next()), JSON.stringify(lr.return('r1')), JSON.stringify(lr.next()), JSON.stringify(lr.return('r2')), log.join('|'));
