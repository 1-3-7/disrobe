<?php

function out_of_loop(array $rows): string
{
    $out = '';
    foreach ($rows as $row) {
        if ($row === 3) {
            goto after;
        }
        $out = $out . $row . ',';
    }
    $out = $out . 'complete,';
    after:
    $out = $out . 'after';

    return $out;
}

function backward(int $limit): string
{
    $out = '';
    $i = 0;
    top:
    $i = $i + 1;
    $out = $out . $i . ',';
    if ($i < $limit) {
        goto top;
    }

    return $out;
}

echo out_of_loop([1, 2, 3, 4]), "\n";
echo out_of_loop([1, 2]), "\n";
echo backward(3), "\n";
