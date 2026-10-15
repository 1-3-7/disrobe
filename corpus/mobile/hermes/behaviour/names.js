var log = [];

function report(value) {
  log.push('global ' + value);
  return value * 2;
}

function label() {
  return 'outer';
}

var tools = {
  report: function (value) {
    return report(value) + 1;
  },
  label() {
    return 'label:' + label();
  },
  nested: function () {
    return [1, 2].map(function (x) {
      return report(x);
    });
  }
};

var shadow = function report(value) {
  return value > 0 ? report(value - 1) + value : 0;
};

function fact(n) {
  return n <= 1 ? 1 : n * fact(n - 1);
}

var savedFact = fact;
fact = function (n) {
  return -n;
};

print(tools.report(5), tools.label(), tools.nested().join('+'), shadow(3), log.join(','));
print(tools.report.name, tools.label.name, shadow.name, savedFact.name);
print(savedFact(4));
