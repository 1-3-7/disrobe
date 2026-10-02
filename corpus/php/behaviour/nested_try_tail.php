<?php
function run(int $a, int $b): array
{
    $out = [];
    try {
        $out[] = intdiv(20, $a);
        try {
            $out[] = 7 % ($b - 2);
        } catch (DivisionByZeroError $error) {
            $out[] = 'inner';
        } finally {
            $out[] = 'inner-finally';
        }
    } catch (DivisionByZeroError $error) {
        $out[] = 'outer';
    }
    try {
        $out[] = $a - $b;
        try {
            $out[] = intdiv($a, $b - 1);
        } catch (DivisionByZeroError $error) {
            $out[] = 'deep';
        } finally {
            $out[] = $b;
        }
    } catch (DivisionByZeroError $error) {
        $out[] = 'never';
    } finally {
        $out[] = 'outer-finally';
    }
    $out[] = $a * $b;
    return $out;
}

echo implode(' ', run(4, 2)), "\n";
echo implode(' ', run(0, 1)), "\n";
echo implode(' ', run(5, 6)), "\n";
