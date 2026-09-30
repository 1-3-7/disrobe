<?php

function day_kind(string $day): string
{
    switch ($day) {
        case 'sat':
        case 'sun':
            $kind = 'weekend';
            break;
        case 'fri':
            $kind = 'almost ';
        case 'mon':
        case 'tue':
            $kind = ($kind ?? '') . 'weekday';
            break;
        default:
            $kind = 'unknown';
    }

    return $kind;
}

function small(int $n): string
{
    $out = '';
    switch ($n) {
        default:
            $out .= 'd';
        case 1:
            $out .= '1';
        case 2:
            $out .= '2';
            break;
        case 3:
            $out .= '3';
            return $out . '!';
    }

    return $out;
}

function loose(mixed $v): string
{
    switch ($v) {
        case 0:
            return 'zero';
        case '1':
            return 'one';
        case 2.5:
            return 'two and a half';
        case null:
            return 'null-ish';
    }

    return 'other';
}

function describe(int|string $v): string
{
    return match ($v) {
        1, 2, 3 => 'small',
        'a', 'b' => 'letter',
        10 => 'ten',
        default => 'other:' . $v,
    };
}

function band(int $n): string
{
    return match (true) {
        $n < 0 => 'neg',
        $n < 10 => 'digit',
        $n < 100 => 'tens',
        default => 'large',
    };
}

foreach (['sat', 'fri', 'mon', 'wed'] as $d) {
    echo $d, ': ', day_kind($d), "\n";
}
foreach ([0, 1, 2, 3, 9] as $n) {
    echo $n, ': ', small($n), "\n";
}
foreach ([0, '1', 2.5, null, 'x', '0'] as $v) {
    echo var_export($v, true), ': ', loose($v), "\n";
}
foreach ([1, 3, 'a', 10, 'z', 11] as $v) {
    echo $v, ': ', describe($v), "\n";
}
foreach ([-3, 4, 55, 1000] as $n) {
    echo $n, ': ', band($n), "\n";
}
try {
    echo match (99) { 1 => 'one' }, "\n";
} catch (\UnhandledMatchError $e) {
    echo get_class($e), ': ', $e->getMessage(), "\n";
}
