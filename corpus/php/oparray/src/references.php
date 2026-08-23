<?php

function alias_scalar(int $seed): string
{
    $a = $seed;
    $b = &$a;
    $b = $b + 10;
    $a = $a * 2;

    return $a . '/' . $b;
}

function alias_dim(int $seed): string
{
    $rows = [$seed, $seed + 1, $seed + 2];
    $slot = &$rows[1];
    $slot = 99;
    $slot = $slot + 1;

    return $rows[0] . '/' . $rows[1] . '/' . $rows[2];
}

function alias_property(int $seed): string
{
    $box = new stdClass();
    $box->n = $seed;
    $held = &$box->n;
    $held = $held + 5;

    return $box->n . '/' . $held;
}

function alias_into_property(int $seed): string
{
    $box = new stdClass();
    $source = $seed;
    $box->mirror = &$source;
    $source = $source + 3;

    return $box->mirror . '/' . $source;
}

function build_list(int $seed): array
{
    return [$seed, $seed + 1];
}

function join_flat(array $rows): string
{
    $out = '';
    foreach ($rows as $row) {
        $out = $out . $row . ',';
    }

    return $out;
}

echo alias_scalar(1), "\n";
echo alias_dim(2), "\n";
echo alias_property(3), "\n";
echo alias_into_property(4), "\n";
echo join_flat(build_list(5)), "\n";
