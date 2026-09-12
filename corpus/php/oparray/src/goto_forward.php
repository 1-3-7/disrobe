<?php

function classify(int $n): string
{
    $out = '';
    if ($n > 0) {
        goto done;
    }
    $out = $out . 'neg,';
    done:
    $out = $out . 'end';

    return $out;
}

function skip_middle(int $n): string
{
    $out = 'a,';
    if ($n === 1) {
        goto tail;
    }
    $out = $out . 'b,';
    if ($n === 2) {
        goto tail;
    }
    $out = $out . 'c,';
    tail:
    $out = $out . 'z';

    return $out;
}

echo classify(1), "\n";
echo classify(-1), "\n";
echo skip_middle(1), "\n";
echo skip_middle(2), "\n";
echo skip_middle(3), "\n";
