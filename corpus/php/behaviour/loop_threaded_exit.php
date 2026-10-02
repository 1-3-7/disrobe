<?php
function inverted(int $limit, int $d): array
{
    $out = [];
    foreach ([1, 2] as $round) {
        try {
            $out[] = $round % $d;
            $n = 0;
            do {
                $n++;
                $out[] = $n * $round;
                if ($n + $d > 6) {
                    continue;
                }
                $out[] = 'step';
            } while ($n < $limit);
        } catch (DivisionByZeroError $error) {
            $out[] = 'zero';
        } finally {
            $out[] = 'done';
        }
    }
    return $out;
}

function chained(int $a, int $c, int $d): array
{
    $out = [];
    if ($a < 11) {
        try {
            $a = 11 % (($d + $c) % 3);
            $n = 0;
            do {
                $n++;
                $out[] = $n;
            } while ($n < 2 && ($d <= $c && $c > 4 || $n === 1));
        } catch (DivisionByZeroError $error) {
            $out[] = 'zero';
        } finally {
            $out[] = $d;
        }
    }
    $out[] = $a;
    return $out;
}

function breaks(int $a, int $c, int $e): array
{
    $out = [];
    try {
        $out[] = 6 % $a;
        if ($a === $c % 4 && $e > 4) {
            for ($i = 0; $i <= $c; $i++) {
                $out[] = $i;
                if ($c % 4 < $i) {
                    break;
                }
            }
        } else {
            $out[] = 'else';
        }
    } catch (DivisionByZeroError $error) {
        $out[] = 'zero';
    } finally {
        $out[] = 'finally';
    }
    return $out;
}

echo implode(' ', inverted(3, 1)), "\n";
echo implode(' ', inverted(2, 0)), "\n";
echo implode(' ', inverted(4, 5)), "\n";
echo implode(' ', chained(3, 6, 2)), "\n";
echo implode(' ', chained(3, 2, 2)), "\n";
echo implode(' ', chained(3, 5, 1)), "\n";
echo implode(' ', chained(20, 5, 1)), "\n";
echo implode(' ', breaks(1, 5, 6)), "\n";
echo implode(' ', breaks(2, 6, 9)), "\n";
echo implode(' ', breaks(0, 4, 9)), "\n";
echo implode(' ', breaks(3, 3, 1)), "\n";
