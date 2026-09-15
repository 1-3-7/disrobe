<?php

function build_list(int $seed): array
{
    return [$seed, $seed + 1, $seed + 2];
}

function build_keyed(int $seed): array
{
    return ['first' => $seed, 'second' => $seed * 2, 7 => $seed * 3];
}

function build_dynamic(string $key, int $value): array
{
    return [$key => $value, 'fixed' => $value + 1];
}

function build_grid(int $seed): array
{
    return [build_list($seed), build_list($seed + 10)];
}

function double_each(array $rows): array
{
    foreach ($rows as &$row) {
        $row = $row * 2;
    }
    return $rows;
}

function tag_each(array $rows): array
{
    foreach ($rows as $key => &$row) {
        $row = $row . ':' . $key;
    }
    return $rows;
}

function sum_only(array $rows): int
{
    $total = 0;
    foreach ($rows as $row) {
        $total = $total + $row;
    }
    return $total;
}

function pairs_only(array $rows): string
{
    $out = '';
    foreach ($rows as $key => $row) {
        $out = $out . $key . '=' . $row . ';';
    }
    return $out;
}

function scale_grid(array $grid, int $factor): array
{
    foreach ($grid as &$line) {
        foreach ($line as &$cell) {
            $cell = $cell * $factor;
        }
    }
    return $grid;
}

function clamp_each(array $rows): array
{
    foreach ($rows as $key => &$row) {
        if ($row < 0) {
            continue;
        }
        if ($row > 100) {
            break;
        }
        $row = $row + $key;
    }
    return $rows;
}

function join_flat(array $rows): string
{
    $out = '';
    foreach ($rows as $row) {
        $out = $out . $row . ',';
    }
    return $out;
}

function join_grid(array $grid): string
{
    $out = '';
    foreach ($grid as $line) {
        $out = $out . join_flat($line) . '|';
    }
    return $out;
}

$values = build_list(1);
echo join_flat(double_each($values)), "\n";
echo join_flat($values), "\n";

echo join_flat(tag_each(build_keyed(2))), "\n";
echo pairs_only(build_keyed(3)), "\n";
echo pairs_only(build_dynamic('dyn', 4)), "\n";

echo sum_only(build_list(5)), "\n";

echo join_grid(scale_grid(build_grid(1), 3)), "\n";

$edges = build_list(-1);
$edges[] = 200;
echo join_flat(clamp_each($edges)), "\n";
