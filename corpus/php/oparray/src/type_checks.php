<?php

function null_identical(?string $v): string
{
    return $v === null ? 'null' : 'set';
}

function null_not_identical(?string $v): string
{
    return $v !== null ? 'set' : 'null';
}

function kinds(mixed $v): string
{
    $out = '';
    $out = $out . (is_int($v) ? 'i' : '-');
    $out = $out . (is_string($v) ? 's' : '-');
    $out = $out . (is_array($v) ? 'a' : '-');
    $out = $out . (is_bool($v) ? 'b' : '-');
    $out = $out . (is_float($v) ? 'f' : '-');
    $out = $out . (is_null($v) ? 'n' : '-');
    $out = $out . (is_object($v) ? 'o' : '-');

    return $out;
}

echo null_identical(null), "\n";
echo null_identical('x'), "\n";
echo null_not_identical(null), "\n";
echo kinds(1), "\n";
echo kinds('a'), "\n";
echo kinds(null), "\n";
