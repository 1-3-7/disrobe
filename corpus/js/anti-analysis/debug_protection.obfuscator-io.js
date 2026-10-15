const callController = (function () {
  let firstCall = true;
  return function (context, fn) {
    const rfn = firstCall ? function () {
      if (fn) {
        const res = fn.apply(context, arguments);
        fn = null;
        return res;
      }
    } : function () {};
    firstCall = false;
    return rfn;
  };
}());
(function () {
  callController(this, function () {
    const regExp1 = new RegExp('function *\\( *\\)');
    const regExp2 = new RegExp('\\+\\+ *(?:[a-zA-Z_$][0-9a-zA-Z_$]*)', 'i');
    const result = debugProtection('init');
    if (!regExp1.test(result + 'chain') || !regExp2.test(result + 'input')) {
      result('0');
    } else {
      debugProtection();
    }
  })();
}());
function debugProtection(ret) {
  function debuggerProtection(counter) {
    if (typeof counter === 'string') {
      return function (arg) {}.constructor('while (true) {}').apply('counter');
    } else {
      if (('' + counter / counter).length !== 1 || counter % 20 === 0) {
        (function () { return true; }).constructor('debu' + 'gger').call('action');
      } else {
        (function () { return false; }).constructor('debu' + 'gger').apply('stateObject');
      }
    }
    debuggerProtection(++counter);
  }
  try {
    if (ret) {
      return debuggerProtection;
    } else {
      debuggerProtection(0);
    }
  } catch (y) {}
}
function scale(values, factor) {
  return values.map((v) => v * factor);
}
console.log("unlocked: " + scale([1, 2, 3], 7).join(","));
