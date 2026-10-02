<?php
function run(int $x, int $y): array
{
    $out = [];
    try {
        $out[] = intdiv(12, $x);
        if ($y > 1) {
            $n = 0;
            while ($n < 3 && ($x === 1 && $y > 0 || $n === 0)) {
                $n++;
                $out[] = $n * $y;
            }
        } else {
            $out[] = 'low';
        }
    } catch (DivisionByZeroError $error) {
        $out[] = 'zero';
    } finally {
        $out[] = 'end';
    }
    return $out;
}

echo implode(' ', run(1, 2)), "\n";
echo implode(' ', run(2, 5)), "\n";
echo implode(' ', run(0, 4)), "\n";
echo implode(' ', run(3, 1)), "\n";
