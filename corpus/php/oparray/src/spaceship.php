<?php

function compare_numbers(int $left, int $right): int
{
    return $left <=> $right;
}

function compare_strings(string $left, string $right): int
{
    return $left <=> $right;
}

function describe(int $left, int $right): string
{
    $order = $left <=> $right;
    if ($order < 0) {
        return 'before';
    }
    if ($order > 0) {
        return 'after';
    }

    return 'same';
}

function rank(int $seed): string
{
    $out = '';
    $out = $out . compare_numbers($seed, 5) . ',';
    $out = $out . compare_numbers(5, $seed) . ',';
    $out = $out . compare_numbers($seed, $seed) . ',';

    return $out;
}

echo compare_numbers(1, 2), "\n";
echo compare_numbers(2, 1), "\n";
echo compare_numbers(3, 3), "\n";
echo compare_strings('a', 'b'), "\n";
echo compare_strings('b', 'a'), "\n";
echo compare_strings('a', 'a'), "\n";
echo describe(1, 2), "\n";
echo describe(2, 1), "\n";
echo describe(2, 2), "\n";
echo rank(4), "\n";
echo rank(5), "\n";
echo rank(6), "\n";
