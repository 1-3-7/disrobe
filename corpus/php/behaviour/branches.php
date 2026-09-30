<?php

function classify(int $n): string
{
    if ($n < 0) {
        $kind = 'negative';
    } elseif ($n === 0) {
        $kind = 'zero';
    } elseif ($n % 2 === 0) {
        if ($n > 10) {
            $kind = 'big even';
        } else {
            $kind = 'small even';
        }
    } else {
        $kind = 'odd';
    }

    return $kind;
}

function grade(int $score): string
{
    if ($score >= 90) {
        return 'A';
    }
    if ($score >= 80) {
        return 'B';
    } elseif ($score >= 70) {
        return 'C';
    }

    return 'F';
}

function both(bool $a, bool $b): string
{
    $out = '';
    if ($a && $b) {
        $out .= 'and ';
    }
    if ($a || $b) {
        $out .= 'or ';
    }
    if (!$a xor $b) {
        $out .= 'xnor ';
    }
    if ($a and !$b) {
        $out .= 'only-a ';
    }

    return $out === '' ? 'none' : rtrim($out);
}

foreach ([-5, 0, 4, 12, 7] as $n) {
    echo $n, ': ', classify($n), "\n";
}
foreach ([95, 85, 75, 10] as $s) {
    echo $s, ' => ', grade($s), "\n";
}
foreach ([[true, true], [true, false], [false, true], [false, false]] as [$a, $b]) {
    echo var_export($a, true), '/', var_export($b, true), ': ', both($a, $b), "\n";
}

$x = 5;
$label = $x > 3 ? ($x > 4 ? 'high' : 'mid') : 'low';
echo $label, "\n";
$flag = $x > 10 || $x < 6 && $x !== 5;
var_dump($flag);
$short = $x ?: 'zero';
echo $short, "\n";
