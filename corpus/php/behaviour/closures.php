<?php

$base = 10;
$byValue = function (int $x) use ($base): int {
    return $x + $base;
};
$base = 1000;
echo $byValue(5), "\n";

$counter = 0;
$inc = function () use (&$counter): int {
    return ++$counter;
};
$inc();
$inc();
echo "counter=$counter\n";

$mul = 3;
$arrow = fn(int $x): int => $x * $mul;
$mul = 99;
echo $arrow(7), "\n";

$nested = fn($a) => fn($b) => $a . '+' . $b;
echo $nested('x')('y'), "\n";

$squares = array_map(fn($n) => $n * $n, [1, 2, 3, 4]);
echo implode(' ', $squares), "\n";

$evens = array_filter([1, 2, 3, 4, 5, 6], function ($n) {
    return $n % 2 === 0;
});
echo implode(' ', $evens), "\n";

$total = array_reduce([1, 2, 3], fn($carry, $n) => $carry + $n, 100);
echo $total, "\n";

function make_counter(int $start): array
{
    $n = $start;

    return [
        'next' => function () use (&$n): int {
            return $n++;
        },
        'peek' => function () use (&$n): int {
            return $n;
        },
    ];
}

$c = make_counter(5);
$c['next']();
$c['next']();
echo 'peek ', $c['peek'](), "\n";

$compose = function (callable ...$fns): Closure {
    return function ($x) use ($fns) {
        foreach ($fns as $fn) {
            $x = $fn($x);
        }

        return $x;
    };
};
echo $compose('strrev', 'strtoupper', fn($s) => "<$s>")('abc'), "\n";

$static = static fn(): string => 'static closure';
echo $static(), "\n";

echo (function () {
    return 'iife';
})(), "\n";

$strlen = strlen(...);
echo $strlen('hello'), "\n";

$acc = [];
$push = function (string $s) use (&$acc): void {
    $acc[] = $s;
};
$push('a');
$push('b');
echo implode('', $acc), "\n";

$byValArr = [1];
$f = function () use ($byValArr) {
    $byValArr[] = 2;

    return count($byValArr);
};
echo $f(), ' ', count($byValArr), "\n";
