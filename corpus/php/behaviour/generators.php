<?php

function count_to(int $n): Generator
{
    for ($i = 1; $i <= $n; $i++) {
        yield $i;
    }
}

function keyed(): Generator
{
    yield 'a' => 1;
    yield 'b' => 2;
    yield 10 => 'ten';
    yield 'no key';
}

function inner(): Generator
{
    yield 1;
    yield 2;

    return 'inner done';
}

function outer(): Generator
{
    yield 0;
    $result = yield from inner();
    yield $result;
    yield from ['x' => 'X', 'y' => 'Y'];
    yield from count_to(2);
}

function accumulator(): Generator
{
    $total = 0;
    while (true) {
        $value = yield $total;
        if ($value === null) {
            return $total;
        }
        $total += $value;
    }
}

function fib(): Generator
{
    [$a, $b] = [0, 1];
    while (true) {
        yield $a;
        [$a, $b] = [$b, $a + $b];
    }
}

function with_finally(): Generator
{
    try {
        yield 'first';
        yield 'second';
    } finally {
        echo "[gen cleanup]\n";
    }
}

foreach (count_to(4) as $k => $v) {
    echo "$k=>$v ";
}
echo "\n";

foreach (keyed() as $k => $v) {
    echo var_export($k, true), '=>', $v, ' ';
}
echo "\n";

foreach (outer() as $k => $v) {
    echo "$k:$v ";
}
echo "\n";

$acc = accumulator();
$acc->current();
$acc->send(5);
$acc->send(10);
echo 'running ', $acc->current(), "\n";
$acc->send(null);
echo 'returned ', $acc->getReturn(), "\n";

$out = [];
foreach (fib() as $i => $f) {
    if ($i >= 10) {
        break;
    }
    $out[] = $f;
}
echo implode(',', $out), "\n";

$g = with_finally();
echo $g->current(), "\n";
unset($g);
echo "after unset\n";

$gen = (function () {
    $received = yield 'hello';
    echo "got $received\n";
    yield 'bye';
})();
echo $gen->current(), "\n";
echo $gen->send('world'), "\n";

echo implode(' ', iterator_to_array(count_to(3), false)), "\n";

$lazy = (fn() => yield from [7, 8, 9])();
foreach ($lazy as $v) {
    echo $v;
}
echo "\n";
