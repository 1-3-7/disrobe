async function double(x) {
  return x * 2;
}

async function chain(n) {
  var a = await double(n);
  var b = await double(a);
  return a + b;
}

async function failing() {
  await null;
  throw new Error('async failure');
}

async function sequence() {
  var out = [];
  for (var i = 0; i < 3; i++) {
    out.push(await double(i));
  }
  try {
    await failing();
  } catch (e) {
    out.push(e.message);
  }
  return out.join(',');
}

var arrowAsync = async function (v) { return (await chain(v)) + 1; };

sequence()
  .then(function (s) { print('sequence', s); return chain(5); })
  .then(function (c) { print('chain', c); return arrowAsync(1); })
  .then(function (v) { print('arrow', v); return Promise.all([double(1), double(2)]); })
  .then(function (all) { print('all', all.join('/')); });
print('sync end');
