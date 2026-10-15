var log = [];

function* guarded(label) {
  try {
    log.push(label + ':start');
    yield 1;
    yield 2;
  } finally {
    log.push(label + ':cleanup');
  }
}

var g = guarded('a');
print(JSON.stringify(g.next()), JSON.stringify(g.return(42)), JSON.stringify(g.next()));
print(log.join(','));

function* nestedFinally() {
  try {
    try {
      yield 'inner';
    } finally {
      log.push('inner-finally');
    }
  } finally {
    log.push('outer-finally');
  }
}

log = [];
var n = nestedFinally();
n.next();
print(JSON.stringify(n.return('done')), log.join(','));

function* overriding() {
  try {
    yield 'x';
  } finally {
    log.push('override');
    return 'overridden';
  }
}

log = [];
var o = overriding();
o.next();
print(JSON.stringify(o.return('ignored')), log.join(','));

function makeIterable(name) {
  var i = 0;
  var source = {};
  source[Symbol.iterator] = function () {
    return {
      next: function () {
        i++;
        return { value: name + i, done: i > 3 };
      },
      return: function () {
        log.push(name + ':closed');
        return {};
      }
    };
  };
  return source;
}

function* relay(source) {
  for (var item of source) {
    yield item;
  }
}

log = [];
var r = relay(makeIterable('src'));
print(r.next().value, r.next().value);
print(JSON.stringify(r.return('stop')), log.join(','));

function* pairs(outer) {
  for (var row of outer) {
    for (var cell of row) {
      yield cell;
    }
  }
}

log = [];
var p = pairs([makeIterable('row'), makeIterable('next')]);
print(p.next().value, p.next().value);
print(JSON.stringify(p.return('cut')), log.join(','));

log = [];
for (var v of guarded('b')) {
  if (v === 1) {
    break;
  }
}
print(log.join(','));

log = [];
var t = guarded('c');
t.next();
try {
  t.throw(new Error('bang'));
} catch (e) {
  print('thrown', e.message);
}
print(log.join(','));

function* failingCleanup() {
  try {
    yield 1;
  } finally {
    log.push('failing');
    throw new Error('cleanup failed');
  }
}

log = [];
var fc = failingCleanup();
fc.next();
try {
  fc.return(5);
} catch (e) {
  print('cleanup error', e.message, log.join(','));
}

function* counting() {
  var total = 0;
  try {
    while (true) {
      total += yield total;
    }
  } finally {
    log.push('total=' + total);
  }
}

log = [];
var c = counting();
c.next();
c.next(5);
c.next(7);
print(JSON.stringify(c.return(-1)), log.join(','));
var fresh = counting();
print(JSON.stringify(fresh.return('early')), log.join(','));

function* conditionalCleanup(verbose) {
  try {
    yield 'work';
  } finally {
    if (verbose) {
      log.push('verbose-cleanup');
    } else {
      log.push('quiet-cleanup');
    }
    log.push('cleanup-done');
  }
}

log = [];
var q1 = conditionalCleanup(true);
q1.next();
var q2 = conditionalCleanup(false);
q2.next();
print(JSON.stringify(q1.return('v')), JSON.stringify(q2.return('q')), log.join(','));

function* drainingCleanup(items) {
  try {
    yield items.length;
  } finally {
    while (items.length > 0) {
      log.push('drain:' + items.pop());
    }
  }
}

log = [];
var d = drainingCleanup([1, 2, 3]);
d.next();
print(JSON.stringify(d.return('drained')), log.join(','));

function* cleanupThatYields() {
  try {
    yield 'body';
  } finally {
    var answer = yield 'closing';
    log.push('closed with ' + answer);
  }
}

log = [];
var y = cleanupThatYields();
y.next();
print(JSON.stringify(y.return('final')), JSON.stringify(y.next('ack')), log.join(','));
