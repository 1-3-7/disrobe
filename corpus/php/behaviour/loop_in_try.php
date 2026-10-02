<?php
function run(int $d, int $b, int $e): array
{
    $out = [];
    $t = [];
    try {
        $n = 0;
        do {
            $n++;
            $t[] = (15 * $d) % 97;
        } while ($n < 3 && (!(intdiv($d, 3) === ($b % 7)) || $n === 1));
    } catch (DivisionByZeroError $error) {
        $out[] = 'zero';
    } finally {
        $out[] = $e;
    }
    try {
        $k = 0;
        do {
            $k++;
            $t[] = intdiv(12, $b - $k);
        } while ($k < 4 && ($d > 2 || $k === 1));
    } catch (DivisionByZeroError $error) {
        $out[] = 'caught';
    } finally {
        $out[] = $k;
    }
    $out[] = count($t);
    $out[] = implode(',', $t);
    return $out;
}

echo implode(' ', run(5, 7, 3)), "\n";
echo implode(' ', run(3, 8, 4)), "\n";
echo implode(' ', run(1, 2, 5)), "\n";
