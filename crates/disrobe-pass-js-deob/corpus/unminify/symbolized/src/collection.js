export function groupBy(records, selector) {
  var groups = {};
  for (var index = 0; index < records.length; index++) {
    var record = records[index];
    var bucket = selector(record);
    if (!groups[bucket]) {
      groups[bucket] = [];
    }
    groups[bucket].push(record);
  }
  return groups;
}

export function partition(values, predicate) {
  var matched = [];
  var rejected = [];
  values.forEach(function (value, position) {
    if (predicate(value, position)) {
      matched.push(value);
    } else {
      rejected.push(value);
    }
  });
  return [matched, rejected];
}

export function chunk(source, size) {
  if (size <= 0) {
    throw new RangeError('size must be positive');
  }
  var result = [];
  var offset = 0;
  while (offset < source.length) {
    result.push(source.slice(offset, offset + size));
    offset = offset + size;
  }
  return result;
}

export function mergeDeep(target, patch) {
  var output = {};
  var keys = Object.keys(target).concat(Object.keys(patch));
  for (var cursor = 0; cursor < keys.length; cursor++) {
    var name = keys[cursor];
    var left = target[name];
    var right = patch[name];
    if (left && right && typeof left === 'object' && typeof right === 'object') {
      output[name] = mergeDeep(left, right);
    } else {
      output[name] = right === undefined ? left : right;
    }
  }
  return output;
}
