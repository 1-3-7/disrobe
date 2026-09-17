<?php

function greet(string $name, int $score): string
{
    return "Hello $name, score=$score!";
}

function label(string $prefix, string $middle, string $suffix): string
{
    return "$prefix-$middle-$suffix";
}

function leading(string $name): string
{
    return "$name trails";
}

function braced(string $name, int $count): string
{
    return "{$name} has {$count} items";
}

function nested(string $outer, string $inner): string
{
    $combined = "$outer/$inner";

    return "[$combined]";
}

echo greet('Ada', 42), "\n";
echo greet('Bob', 7), "\n";
echo label('a', 'b', 'c'), "\n";
echo leading('x'), "\n";
echo braced('cart', 3), "\n";
echo nested('one', 'two'), "\n";
