<?php

function add(int $a, int $b): int
{
    $r = $a + $b;

    return $r;
}

function greet(string $who): string
{
    return "hi " . $who;
}

function pick(int $x): string
{
    if ($x > 0) {
        return "pos";
    }

    return "nonpos";
}

$s = add(40, 2);
echo $s, "\n";
echo greet("ada"), "\n";
echo pick(5), "\n";
echo pick(-3), "\n";
$base = 9;
$nums = [$base, 1, 2, 3];
echo count($nums), "\n";
