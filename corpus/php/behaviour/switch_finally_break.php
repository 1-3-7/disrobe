<?php
function run(int $k, int $a): array
{
    $out = [];
    switch ($k % 3) {
        case 0:
            $out[] = 'zero';
            try {
                $out[] = intdiv(9, $a);
            } catch (DivisionByZeroError $error) {
                $out[] = 'caught';
            } finally {
                $out[] = 'finally';
            }
            break;
        case 1:
            if ($a > 2) {
                $out[] = 'big';
            }
            $out[] = 'one';
            break;
    }
    $out[] = $k + $a;
    return $out;
}

echo implode(' ', run(3, 3)), "\n";
echo implode(' ', run(0, 0)), "\n";
echo implode(' ', run(4, 5)), "\n";
echo implode(' ', run(2, 1)), "\n";
