<?php
function run(int $a, int $b, int $c): array
{
    $out = [];
    if ($a > 2) {
        $out[] = 'then';
        try {
            $out[] = intdiv(10, $b - 3);
        } catch (DivisionByZeroError $error) {
            $out[] = 'zero';
        } finally {
            $out[] = $c;
        }
    } elseif ($b > 4) {
        $out[] = 'elseif';
    } else {
        $out[] = 'else';
    }
    if ($b % 2 === 1 && $c > 1) {
        try {
            $out[] = 12 % ($a - 4);
        } catch (DivisionByZeroError $error) {
            $out[] = 'caught';
        } finally {
            $out[] = $a + $b;
        }
    } else {
        $out[] = 'other';
    }
    if ($c < 5) {
        try {
            $out[] = $a * $c;
        } finally {
            $out[] = 'done';
        }
    } else {
        $out[] = 'skipped';
    }
    $out[] = $a + $b + $c;
    return $out;
}

echo implode(' ', run(5, 3, 2)), "\n";
echo implode(' ', run(1, 6, 7)), "\n";
echo implode(' ', run(4, 5, 1)), "\n";
echo implode(' ', run(0, 2, 9)), "\n";
echo implode(' ', run(3, 7, 3)), "\n";
