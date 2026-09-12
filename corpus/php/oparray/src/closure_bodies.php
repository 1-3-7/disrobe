<?php

function make_adder(int $base): callable
{
    $step = function (int $value) use ($base): int {
        return $value + $base;
    };

    return $step;
}

function make_scaler(int $factor, int $offset): callable
{
    return function (int $value) use ($factor, $offset): int {
        $scaled = $value * $factor;

        return $scaled + $offset;
    };
}

function make_counter(): callable
{
    $plain = function (int $value): int {
        if ($value < 0) {
            return 0;
        }

        return $value + 1;
    };

    return $plain;
}

function pick(int $base, bool $rising): callable
{
    $increase = function (int $value) use ($base): int {
        return $value + $base;
    };
    $decrease = function (int $value) use ($base): int {
        return $value - $base;
    };

    return $rising ? $increase : $decrease;
}

function pair(int $base, bool $rising): callable
{
    $up = function (int $value) use ($base): int { return $value + $base; }; $down = function (int $value) use ($base): int { return $value * $base; };

    return $rising ? $up : $down;
}

function apply_twice(callable $fn, int $seed): int
{
    $once = $fn($seed);

    return $fn($once);
}

$add = make_adder(10);
$scale = make_scaler(3, 1);
$count = make_counter();

echo $add(5), "\n";
echo $scale(4), "\n";
echo $count(7), "\n";
echo $count(-2), "\n";
echo apply_twice($add, 1), "\n";
echo apply_twice($scale, 2), "\n";
echo pick(3, true)(10), "\n";
echo pick(3, false)(10), "\n";
echo pair(4, true)(10), "\n";
echo pair(4, false)(10), "\n";
