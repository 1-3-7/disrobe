<?php

function simple(array $values): string
{
    [$first, $second] = $values;
    return "$first:$second";
}

function skipped(array $values): string
{
    [$first, , $third] = $values;
    return "$first:$third";
}

function keyed(array $values): string
{
    ['left' => $left, 7 => $seventh] = $values;
    return "$left:$seventh";
}

function nested(array $values): string
{
    [$head, ['value' => $inside]] = $values;
    return "$head:$inside";
}

function reused(array $values): string
{
    $copy = ([$values] = $values);
    return $values . ':' . $copy[0];
}

function nested_multiple(array $values): string
{
    [[$first, $second], $tail] = $values;
    return "$first:$second:$tail";
}

function pair(int $first, int $second): array
{
    return [$first, $second];
}

function triple(int $first, int $second, int $third): array
{
    return [$first, $second, $third];
}

function keyed_values(int $left, int $seventh): array
{
    return ['left' => $left, 7 => $seventh];
}

function nested_values(int $head, int $inside): array
{
    return [$head, ['value' => $inside]];
}

function nested_multiple_values(int $first, int $second, int $tail): array
{
    return [[$first, $second], $tail];
}

echo simple(pair(2, 3)), "\n";
echo skipped(triple(5, 11, 13)), "\n";
echo keyed(keyed_values(17, 19)), "\n";
echo nested(nested_values(23, 29)), "\n";
echo reused(pair(31, 37)), "\n";
echo nested_multiple(nested_multiple_values(41, 43, 47)), "\n";
