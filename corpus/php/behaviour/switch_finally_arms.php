<?php
function run(int $k, int $a): array
{
    $out = [];
    switch ($k % 4) {
        case 0:
            $out[] = 'zero';
            try {
                $out[] = intdiv(12, $a);
            } catch (DivisionByZeroError $error) {
                $out[] = 'caught';
            } finally {
                $out[] = 'first';
            }
            break;
        case 1:
        case 2:
            try {
                $out[] = 7 % $a;
            } catch (DivisionByZeroError $error) {
                $out[] = 'caught';
            } finally {
                $out[] = 'second';
            }
            break;
        default:
            $out[] = 'other';
            if ($a > 2) {
                $out[] = 'wide';
            }
    }
    $out[] = $k + $a;
    return $out;
}

foreach ([[0, 3], [0, 0], [1, 2], [2, 0], [3, 5], [7, 1]] as [$k, $a]) {
    echo implode(' ', run($k, $a)), "\n";
}
