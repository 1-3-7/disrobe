<?php
function nested(int $a, int $b, array $t): array
{
    $out = [];
    try {
        $out[] = 12 % $a;
        if (in_array($a + $b, $t, true)) {
            $out[] = 'listed';
            try {
                $out[] = 9 % $b;
                $t[] = $b;
            } catch (DivisionByZeroError $error) {
                $out[] = 'inner zero';
            }
        } else {
            if ($a > $b && $b > 0) {
                $out[] = 'ordered';
            } elseif ($a < 3 || $b === 2) {
                $out[] = 'small';
            }
            $out[] = $a + $b;
        }
    } catch (DivisionByZeroError $error) {
        $out[] = 'outer zero';
    }
    $out[] = count($t);
    return $out;
}

function compound(int $a, int $b, int $c): array
{
    $out = [];
    if ($a > $c || $b === 6) {
        if ($a * 7 % 97 < $c + 7 && $b > 2) {
            $out[] = 'both';
            try {
                $c = $a % ($b % 3);
                $out[] = $c;
            } catch (DivisionByZeroError $error) {
                $out[] = 'zero';
            }
        } else {
            $out[] = 'either';
            if ($b !== 4) {
                $out[] = 'not four';
            } elseif ($c <= 18) {
                $out[] = 'low';
            } else {
                $out[] = 'high';
            }
        }
    } elseif ($c >= 3 || $a === 1) {
        $out[] = 'fallback';
    }
    $out[] = $a + $b + $c;
    return $out;
}

foreach ([[3, 1, [4]], [0, 2, []], [4, 0, [4]], [5, 2, [7]], [2, 2, []], [1, 5, [6]]] as [$a, $b, $t]) {
    echo implode(' ', nested($a, $b, $t)), "\n";
}
foreach ([[14, 4, 0], [14, 3, 0], [9, 6, 1], [9, 3, 1], [9, 4, 30], [1, 1, 5], [0, 0, 0], [2, 6, 2], [5, 4, 2]] as [$a, $b, $c]) {
    echo implode(' ', compound($a, $b, $c)), "\n";
}
