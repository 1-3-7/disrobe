<?php

function classify_match(int $value): string
{
    return match ($value) {
        1, 2 => 'low',
        7 => 'seven',
        9 => 'nine',
        default => 'other',
    };
}

function classify_string_match(string $value): string
{
    return match ($value) {
        'red', 'green' => 'color',
        'up' => 'direction',
        'ready' => 'state',
        default => 'other',
    };
}

echo classify_match(2), "\n";
echo classify_match(7), "\n";
echo classify_match(9), "\n";
echo classify_match(99), "\n";
echo classify_string_match('green'), "\n";
echo classify_string_match('up'), "\n";
echo classify_string_match('ready'), "\n";
echo classify_string_match('unknown'), "\n";
