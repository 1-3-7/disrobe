function Event(kind) {
  this.kind = kind;
}
Event.prototype.describe = function () {
  return 'event:' + this.kind;
};

function Wrapper(value) {
  if (value > 10) {
    return { wrapped: value };
  }
  this.value = value;
}

var registry = {
  shapes: {
    Point: function (x, y) {
      this.x = x;
      this.y = y;
    }
  }
};

function pick(flag) {
  return flag ? Event : Wrapper;
}

function fire(timedOut, failed) {
  var events = [];
  events.push(new Event(timedOut ? 'timeout' : 'error'));
  if (failed) {
    events.push(new Event(timedOut ? 'late' : 'broken'));
  }
  return events.map(function (e) {
    return e.describe();
  }).join(',');
}

var args = [3, 4];
var p = new registry.shapes.Point(...args);
print(fire(true, false), fire(false, true));
print(new Wrapper(5).value, new Wrapper(50).wrapped, new Wrapper(50) instanceof Wrapper);
print(p.x + p.y, p instanceof registry.shapes.Point);
print(new (pick(true))('picked').describe(), new (pick(false))(7).value);
var ctors = [Event, Wrapper];
for (var i = 0; i < ctors.length; i++) {
  var made = new ctors[i](i + 1);
  print(i, Object.keys(made).join('|'));
}
