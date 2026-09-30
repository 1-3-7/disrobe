<?php

function greet(string $greeting, string $name = 'you', string $punct = '!'): string
{
    return "$greeting, $name$punct";
}

function total(int ...$nums): int
{
    return array_sum($nums);
}

function head_tail(string $sep, string ...$parts): string
{
    return count($parts) . ':' . implode($sep, $parts);
}

function describe(int $a, ?int $b = null, int|string $c = 'c', array $d = []): string
{
    return json_encode([$a, $b, $c, $d]);
}

function &ref_slot(array &$arr, string $key): mixed
{
    $arr[$key] ??= 0;

    return $arr[$key];
}

function bump(int &$n, int $by = 1): void
{
    $n += $by;
}

echo greet('Hi'), "\n";
echo greet('Hi', 'Bob'), "\n";
echo greet('Hi', punct: '?'), "\n";
echo greet(name: 'Eve', greeting: 'Yo'), "\n";

echo total(), ' ', total(1, 2, 3), "\n";
$nums = [4, 5, 6];
echo total(...$nums), ' ', total(1, ...$nums), "\n";
echo head_tail('-', 'a', 'b', 'c'), "\n";
echo head_tail(...['/', 'x', 'y']), "\n";

$args = ['greeting' => 'Hey', 'punct' => '.'];
echo greet(...$args), "\n";

echo describe(1), "\n";
echo describe(1, 2), "\n";
echo describe(1, c: 99), "\n";
echo describe(5, d: [1, 2], b: null), "\n";

$store = [];
$slot = &ref_slot($store, 'hits');
$slot += 10;
$slot++;
echo $store['hits'], "\n";

$v = 1;
bump($v);
bump($v, 5);
echo $v, "\n";

$fn = 'greet';
echo $fn('Dyn'), "\n";
echo call_user_func_array('greet', ['CUFA', 'Z']), "\n";
echo call_user_func('greet', 'CUF', punct: ';'), "\n";

$args2 = ['Pos'];
echo greet(...$args2, ...['name' => 'Named']), "\n";

echo max(...[3, 9, 2]), ' ', min(4, 1, 7), "\n";
echo str_repeat(string: 'ab', times: 3), "\n";

function defaults_from_const(int $x = PHP_INT_SIZE, string $s = PHP_EOL): string
{
    return $x . json_encode($s);
}

echo defaults_from_const(), "\n";

function recurse(int $n): int
{
    return $n <= 1 ? 1 : $n * recurse($n - 1);
}

echo recurse(10), "\n";
