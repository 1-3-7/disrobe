function risky(n) {
  if (n > 2) throw new RangeError('too big: ' + n);
  return n * 2;
}

function guarded(n) {
  try {
    return 'ok ' + risky(n);
  } catch (e) {
    return 'caught ' + e.name + ' ' + e.message;
  }
}

var log = [];
function withFinally(n) {
  try {
    log.push('try' + n);
    if (n === 1) return 'early';
    if (n === 2) throw new Error('boom');
    log.push('after' + n);
  } catch (e) {
    log.push('catch' + n);
    return 'from-catch';
  } finally {
    log.push('finally' + n);
  }
  return 'end';
}

function nestedTry() {
  var trace = '';
  try {
    try {
      throw new TypeError('inner');
    } catch (e) {
      trace += 'c1:' + e.message + ';';
      throw new Error('rethrown');
    } finally {
      trace += 'f1;';
    }
  } catch (e2) {
    trace += 'c2:' + e2.message + ';';
  }
  return trace;
}

function loopWithTry(items) {
  var good = 0, bad = 0;
  for (var i = 0; i < items.length; i++) {
    try {
      if (items[i] < 0) throw items[i];
      good += items[i];
    } catch (v) {
      bad += v;
      continue;
    }
  }
  return good + '/' + bad;
}

function optionalCatch() {
  try { null.x; } catch { return 'no binding'; }
}

print(guarded(1), guarded(5));
print(withFinally(0), withFinally(1), withFinally(2), log.join(','));
print(nestedTry());
print(loopWithTry([1, -2, 3, -4, 5]));
print(optionalCatch());
try { undefinedFunction(); } catch (e) { print(e instanceof ReferenceError); }
try { (void 0).prop; } catch (e) { print(e instanceof TypeError); }
var finalValue = (function () { try { return 1; } finally { print('cleanup'); } })();
print(finalValue);
